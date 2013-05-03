/***
  This file is part of PulseAudio.

  Copyright 2008 Colin Guthrie

  PulseAudio is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published
  by the Free Software Foundation; either version 2.1 of the License,
  or (at your option) any later version.

  PulseAudio is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with PulseAudio; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
  USA.
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>

#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif

/* TODO: Replace OpenSSL with NSS */
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>

#include <pulse/xmalloc.h>
#include <pulse/timeval.h>

#include <pulsecore/core-error.h>
#include <pulsecore/core-rtclock.h>
#include <pulsecore/core-util.h>
#include <pulsecore/iochannel.h>
#include <pulsecore/arpa-inet.h>
#include <pulsecore/socket-util.h>
#include <pulsecore/log.h>
#include <pulsecore/parseaddr.h>
#include <pulsecore/macro.h>
#include <pulsecore/memchunk.h>
#include <pulsecore/random.h>

#include "raop_client.h"
#include "rtsp_client.h"
#include "base64.h"

#define FRAMES_PER_PACKET 352
#define AES_CHUNKSIZE 16

#define JACK_STATUS_DISCONNECTED 0
#define JACK_STATUS_CONNECTED 1
#define JACK_TYPE_ANALOG 0
#define JACK_TYPE_DIGITAL 1

#define VOLUME_MIN -144
#define VOLUME_DEF -30
#define VOLUME_MAX 0

#define DEFAULT_RAOP_PORT 5000
#define DEFAULT_AUDIO_PORT 6000
#define DEFAULT_CONTROL_PORT 6001
#define DEFAULT_TIMING_PORT 6002

typedef enum {
    PAYLOAD_TIMING_REQUEST = 0x52,
    PAYLOAD_TIMING_RESPONSE = 0x53,
    PAYLOAD_SYNCHRONIZATION = 0x54,
    PAYLOAD_RETRANSMIT_REQUEST = 0x55,
    PAYLOAD_RETRANSMIT_REPLY = 0x56,
    PAYLOAD_AUDIO_DATA = 0x60
} pa_raop_payload_type;

struct pa_raop_client {
    pa_core *core;
    char *host;
    uint16_t port;
    char *sid;

    pa_rtsp_client *rtsp;

    uint8_t jack_type;
    uint8_t jack_status;

    uint16_t control_port;
    uint16_t timing_port;

    /* Encryption Related bits */
    AES_KEY aes;
    uint8_t aes_iv[AES_CHUNKSIZE]; /* Initialization vector for aes-cbc */
    uint8_t aes_nv[AES_CHUNKSIZE]; /* Next vector for aes-cbc */
    uint8_t aes_key[AES_CHUNKSIZE]; /* Key for aes-cbc */

    pa_socket_client *sc;
    int stream_fd;
    int control_fd;
    int timing_fd;

    uint16_t seq;
    uint32_t rtptime;

    pa_raop_client_setup_cb_t setup_callback;
    void *setup_userdata;

    pa_raop_client_record_cb_t record_callback;
    void *record_userdata;

    pa_raop_client_disconnected_cb_t disconnected_callback;
    void *disconnected_userdata;
};

/**
 * Function to write bits into a buffer.
 * @param buffer Handle to the buffer. It will be incremented if new data requires it.
 * @param bit_pos A pointer to a position buffer to keep track the current write location (0 for MSB, 7 for LSB)
 * @param size A pointer to the byte size currently written. This allows the calling function to do simple buffer overflow checks
 * @param data The data to write
 * @param data_bit_len The number of bits from data to write
 */
static inline void bit_writer(uint8_t **buffer, uint8_t *bit_pos, int *size, uint8_t data, uint8_t data_bit_len) {
    int bits_left, bit_overflow;
    uint8_t bit_data;

    if (!data_bit_len)
        return;

    /* If bit pos is zero, we will definately use at least one bit from the current byte so size increments. */
    if (!*bit_pos)
        *size += 1;

    /* Calc the number of bits left in the current byte of buffer. */
    bits_left = 7 - *bit_pos  + 1;
    /* Calc the overflow of bits in relation to how much space we have left... */
    bit_overflow = bits_left - data_bit_len;
    if (bit_overflow >= 0) {
        /* We can fit the new data in our current byte.
         * As we write from MSB->LSB we need to left shift by the overflow amount. */
        bit_data = data << bit_overflow;
        if (*bit_pos)
            **buffer |= bit_data;
        else
            **buffer = bit_data;
        /* If our data fits exactly into the current byte, we need to increment our pointer. */
        if (0 == bit_overflow) {
            /* Do not increment size as it will be incremented on next call as bit_pos is zero. */
            *buffer += 1;
            *bit_pos = 0;
        } else {
            *bit_pos += data_bit_len;
        }
    } else {
        /* bit_overflow is negative, there for we will need a new byte from our buffer
         * Firstly fill up what's left in the current byte. */
        bit_data = data >> -bit_overflow;
        **buffer |= bit_data;
        /* Increment our buffer pointer and size counter. */
        *buffer += 1;
        *size += 1;
        **buffer = data << (8 + bit_overflow);
        *bit_pos = -bit_overflow;
    }
}

static int rsa_encrypt(uint8_t *text, int len, uint8_t *res) {
    const char n[] =
        "59dE8qLieItsH1WgjrcFRKj6eUWqi+bGLOX1HL3U3GhC/j0Qg90u3sG/1CUtwC"
        "5vOYvfDmFI6oSFXi5ELabWJmT2dKHzBJKa3k9ok+8t9ucRqMd6DZHJ2YCCLlDR"
        "KSKv6kDqnw4UwPdpOMXziC/AMj3Z/lUVX1G7WSHCAWKf1zNS1eLvqr+boEjXuB"
        "OitnZ/bDzPHrTOZz0Dew0uowxf/+sG+NCK3eQJVxqcaJ/vEHKIVd2M+5qL71yJ"
        "Q+87X6oV3eaYvt3zWZYD6z5vYTcrtij2VZ9Zmni/UAaHqn9JdsBWLUEpVviYnh"
        "imNVvYFZeCXg/IdTQ+x4IRdiXNv5hEew==";
    const char e[] = "AQAB";
    uint8_t modules[256];
    uint8_t exponent[8];
    int size;
    RSA *rsa;

    rsa = RSA_new();
    size = pa_base64_decode(n, modules);
    rsa->n = BN_bin2bn(modules, size, NULL);
    size = pa_base64_decode(e, exponent);
    rsa->e = BN_bin2bn(exponent, size, NULL);

    size = RSA_public_encrypt(len, text, res, rsa, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsa);
    return size;
}

static int aes_encrypt(pa_raop_client *c, uint8_t *data, int size) {
    uint8_t *buf;
    int i=0, j;

    pa_assert(c);

    memcpy(c->aes_nv, c->aes_iv, AES_CHUNKSIZE);
    while (i+AES_CHUNKSIZE <= size) {
        buf = data + i;
        for (j=0; j<AES_CHUNKSIZE; ++j)
            buf[j] ^= c->aes_nv[j];

        AES_encrypt(buf, buf, &c->aes);
        memcpy(c->aes_nv, buf, AES_CHUNKSIZE);
        i += AES_CHUNKSIZE;
    }

    return i;
}

static inline void rtrimchar(char *str, char rc) {
    char *sp;

    sp = str + strlen(str) - 1;
    while (sp >= str && *sp == rc) {
        *sp = '\0';
        sp--;
    }
}

static inline uint64_t timeval_to_ntp(struct timeval *tv) {
    uint64_t ntp = 0;

    /* Converting micro seconds to a fraction. */
    ntp = (uint64_t) tv->tv_usec * UINT32_MAX / PA_USEC_PER_SEC;
    /* Moving reference from  1 Jan 1970 to 1 Jan 1900 (seconds). */
    ntp |= (uint64_t) (tv->tv_sec + 0x83aa7e80) << 32;

    return ntp;
}

static int bind_socket(pa_raop_client *c, int fd, uint16_t port) {
    struct sockaddr_in sa4;
#ifdef HAVE_IPV6
    struct sockaddr_in6 sa6;
#endif
    struct sockaddr *sa;
    socklen_t salen;
    int one = 1;

    pa_zero(sa4);
#ifdef HAVE_IPV6
    pa_zero(sa6);
#endif
    if (inet_pton(AF_INET, pa_rtsp_localip(c->rtsp), &sa4.sin_addr) > 0) {
        sa4.sin_family = AF_INET;
        sa4.sin_port = htons(port);
        sa = (struct sockaddr *) &sa4;
        salen = sizeof(sa4);
#ifdef HAVE_IPV6
    } else if (inet_pton(AF_INET6, pa_rtsp_localip(c->rtsp), &sa6.sin6_addr) > 0) {
        sa6.sin6_family = AF_INET6;
        sa6.sin6_port = htons(port);
        sa = (struct sockaddr*) &sa6;
        salen = sizeof(sa6);
#endif
    } else {
        pa_log("Invalid destination '%s'", c->host);
        goto fail;
    }

    one = 1;
#ifdef SO_TIMESTAMP
    if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &one, sizeof(one)) < 0) {
        pa_log("setsockopt(SO_TIMESTAMP) failed: %s", pa_cstrerror(errno));
        goto fail;
    }
#else
    pa_log("SO_TIMESTAMP unsupported on this platform");
    goto fail;
#endif

    one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
        pa_log("setsockopt(SO_REUSEADDR) failed: %s", pa_cstrerror(errno));
        goto fail;
    }

    if (bind(fd, sa, salen) < 0) {
        pa_log("bind() failed: %s", pa_cstrerror(errno));
        goto fail;
    }

    return fd;

fail:
    return -1;
}

static int open_udp_socket(pa_raop_client *c, uint16_t port, uint16_t should_bind) {
    struct sockaddr_in sa4;
#ifdef HAVE_IPV6
    struct sockaddr_in6 sa6;
#endif
    struct sockaddr *sa;
    socklen_t salen;
    sa_family_t af;
    int fd = -1;

    pa_zero(sa4);
#ifdef HAVE_IPV6
    pa_zero(sa6);
#endif
    if (inet_pton(AF_INET, c->host, &sa4.sin_addr) > 0) {
        sa4.sin_family = af = AF_INET;
        sa4.sin_port = htons(port);
        sa = (struct sockaddr *) &sa4;
        salen = sizeof(sa4);
#ifdef HAVE_IPV6
    } else if (inet_pton(AF_INET6, c->host, &sa6.sin6_addr) > 0) {
        sa6.sin6_family = af = AF_INET6;
        sa6.sin6_port = htons(port);
        sa = (struct sockaddr *) &sa6;
        salen = sizeof(sa6);
#endif
    } else {
        pa_log("Invalid destination '%s'", c->host);
        goto fail;
    }

    if ((fd = pa_socket_cloexec(af, SOCK_DGRAM, 0)) < 0) {
        pa_log("socket() failed: %s", pa_cstrerror(errno));
        goto fail;
    }

    /* If the socket queue is full, let's drop packets */
    pa_make_udp_socket_low_delay(fd);
    pa_make_fd_nonblock(fd);

    if (should_bind) {
        if (bind_socket(c, fd, port) < 0) {
            pa_log("bind_socket() failed: %s", pa_cstrerror(errno));
            goto fail;
        }
    }

    if (connect(fd, sa, salen) < 0) {
        pa_log("connect() failed: %s", pa_cstrerror(errno));
        goto fail;
    }

    pa_log_debug("Connected to %s on port %d (SOCK_DGRAM)", c->host, port);
    return fd;

fail:
    if (fd >= 0)
        pa_close(fd);

    return -1;
}

static void rtsp_cb(pa_rtsp_client *rtsp, pa_rtsp_state state, pa_headerlist *headers, void *userdata) {
    pa_raop_client *c = userdata;

    pa_assert(c);
    pa_assert(rtsp);
    pa_assert(rtsp == c->rtsp);

    switch (state) {
        case STATE_CONNECT: {
            uint16_t rand;
            char *sac;

            /* Set the Apple-Challenge key */
            pa_random(&rand, sizeof(rand));
            pa_base64_encode(&rand, AES_CHUNKSIZE, &sac);
            rtrimchar(sac, '=');
            pa_rtsp_add_header(c->rtsp, "Apple-Challenge", sac);

            pa_rtsp_options(c->rtsp);

            pa_xfree(sac);
            break;
        }

        case STATE_OPTIONS: {
            uint8_t rsakey[512];
            char *key, *iv, *sdp;
            const char *ip;
            char *url;
            int i;

            pa_rtsp_remove_header(c->rtsp, "Apple-Challenge");

            /* First of all set the url properly. */
            ip = pa_rtsp_localip(c->rtsp);
            url = pa_sprintf_malloc("rtsp://%s/%s", ip, c->sid);
            pa_rtsp_set_url(c->rtsp, url);
            pa_xfree(url);

            /* Now encrypt our aes_public key to send to the device. */
            i = rsa_encrypt(c->aes_key, AES_CHUNKSIZE, rsakey);
            pa_base64_encode(rsakey, i, &key);
            rtrimchar(key, '=');
            pa_base64_encode(c->aes_iv, AES_CHUNKSIZE, &iv);
            rtrimchar(iv, '=');

            sdp = pa_sprintf_malloc(
                "v=0\r\n"
                "o=iTunes %s 0 IN IP4 %s\r\n"
                "s=iTunes\r\n"
                "c=IN IP4 %s\r\n"
                "t=0 0\r\n"
                "m=audio 0 RTP/AVP 96\r\n"
                "a=rtpmap:96 AppleLossless\r\n"
                "a=fmtp:96 %d 0 16 40 10 14 2 255 0 0 44100\r\n"
                "a=rsaaeskey:%s\r\n"
                "a=aesiv:%s\r\n",
                c->sid, ip,
                c->host,
                FRAMES_PER_PACKET,
                key,
                iv);

            pa_rtsp_announce(c->rtsp, sdp);

            pa_xfree(key);
            pa_xfree(iv);
            pa_xfree(sdp);
            break;
        }

        case STATE_ANNOUNCE: {
            char *trs;

            trs = pa_sprintf_malloc("RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;control_port=%d;timing_port=%d",
                c->control_port,
                c->timing_port);

            pa_rtsp_setup(c->rtsp, trs);

            pa_xfree(trs);
            break;
        }

        case STATE_SETUP: {
            uint32_t stream_port = DEFAULT_AUDIO_PORT;
            char *ajs, *trs, *token, *pc;
            char delimiters[] = ";";
            const char *token_state = NULL;
            uint32_t port = 0;

            ajs = pa_xstrdup(pa_headerlist_gets(headers, "Audio-Jack-Status"));
            trs = pa_xstrdup(pa_headerlist_gets(headers, "Transport"));

            if (ajs) {
                c->jack_type = JACK_TYPE_ANALOG;
                c->jack_status = JACK_STATUS_DISCONNECTED;

                while ((token = pa_split(ajs, delimiters, &token_state))) {
                    if ((pc = strstr(token, "="))) {
                      *pc = 0;
                      if (pa_streq(token, "type") && pa_streq(pc + 1, "digital"))
                          c->jack_type = JACK_TYPE_DIGITAL;
                    } else {
                        if (pa_streq(token, "connected"))
                            c->jack_status = JACK_STATUS_CONNECTED;
                    }
                    pa_xfree(token);
                }

            } else {
                pa_log_warn("Audio-Jack-Status missing");
            }

            token_state = NULL;

            if (trs) {
                /* Now parse out the server port component of the response. */
                while ((token = pa_split(trs, delimiters, &token_state))) {
                    if ((pc = strstr(token, "="))) {
                        *pc = 0;
                        if (pa_streq(token, "control_port")) {
                            port = 0;
                            pa_atou(pc + 1, &port);
                            c->control_port = port;
                        }
                        if (pa_streq(token, "timing_port")) {
                            port = 0;
                            pa_atou(pc + 1, &port);
                            c->timing_port = port;
                        }
                        *pc = '=';
                    }
                    pa_xfree(token);
                }
            } else {
                pa_log_warn("Transport missing");
            }

            pa_xfree(ajs);
            pa_xfree(trs);

            stream_port = pa_rtsp_serverport(c->rtsp);
            if (stream_port == 0)
                goto error;
            if (c->control_port == 0 || c->timing_port == 0)
                goto error;

            pa_log_debug("Using server_port=%d, control_port=%d & timing_port=%d",
                stream_port,
                c->control_port,
                c->timing_port);

            c->stream_fd = open_udp_socket(c, stream_port, 0);
            c->control_fd = open_udp_socket(c, c->control_port, 1);
            c->timing_fd = open_udp_socket(c, c->timing_port, 1);

            if (c->stream_fd <= 0)
                goto error;
            if (c->control_fd <= 0 || c->timing_fd <= 0)
                goto error;

            c->setup_callback(c->control_fd, c->timing_fd, c->setup_userdata);
            pa_rtsp_record(c->rtsp, &c->seq, &c->rtptime);

            break;

error:
            if (c->stream_fd != -1) {
                pa_close(c->stream_fd);
                c->stream_fd = -1;
            }
            if (c->control_fd != -1) {
                pa_close(c->control_fd);
                c->control_fd = -1;
            }
            if (c->timing_fd != -1) {
                pa_close(c->timing_fd);
                c->timing_fd = -1;
            }

            pa_rtsp_client_free(c->rtsp);
            c->rtsp = NULL;

            c->control_port = DEFAULT_CONTROL_PORT;
            c->timing_port = DEFAULT_TIMING_PORT;

            pa_log_error("aborting RTSP setup, failed creating required sockets");

            break;
        }

        case STATE_RECORD: {
            int32_t latency = 0;
            char *alt;

            alt = pa_xstrdup(pa_headerlist_gets(headers, "Audio-Latency"));

            if (alt)
                pa_atoi(alt, &latency);

            c->record_callback(c->setup_userdata);

            pa_xfree(alt);
            break;
        }

        case STATE_FLUSH: {
            pa_log_debug("RAOP: FLUSHED");

            break;
        }

        case STATE_TEARDOWN: {
            pa_log_debug("RAOP: TEARDOWN");

            break;
        }

        case STATE_SET_PARAMETER: {
            pa_log_debug("RAOP: SET_PARAMETER");

            break;
        }

        case STATE_DISCONNECTED: {
            pa_assert(c->disconnected_callback);
            pa_assert(c->rtsp);

            pa_log_debug("RTSP control channel closed");

            pa_rtsp_client_free(c->rtsp);
            c->rtsp = NULL;

            if (c->stream_fd > 0) {
                pa_close(c->stream_fd);
                c->stream_fd = -1;
            }
            if (c->control_fd > 0) {
                pa_close(c->control_fd);
                c->control_fd = -1;
            }
            if (c->timing_fd > 0) {
                pa_close(c->timing_fd);
                c->timing_fd = -1;
            }

            pa_xfree(c->sid);
            c->sid = NULL;

            c->disconnected_callback(c->disconnected_userdata);

            break;
        }
    }
}

pa_raop_client* pa_raop_client_new(pa_core *core, const char *host) {
    pa_raop_client *c = pa_xnew0(pa_raop_client, 1);
    pa_parsed_address a;

    pa_assert(core);
    pa_assert(host);

    if (pa_parse_address(host, &a) < 0)
        return NULL;

    if (a.type ==  PA_PARSED_ADDRESS_UNIX)
        return NULL;

    c->core = core;
    c->stream_fd = -1;
    c->control_fd = -1;
    c->timing_fd = -1;

    c->control_port = DEFAULT_CONTROL_PORT;
    c->timing_port = DEFAULT_TIMING_PORT;

    c->host = pa_xstrdup(a.path_or_host);
    if (a.port)
        c->port = a.port;
    else
        c->port = DEFAULT_RAOP_PORT;

    return c;
}


void pa_raop_client_free(pa_raop_client *c) {
    pa_assert(c);

    if (c->rtsp)
        pa_rtsp_client_free(c->rtsp);
    if (c->sid)
        pa_xfree(c->sid);
    pa_xfree(c->host);
    pa_xfree(c);
}

int pa_raop_client_connect(pa_raop_client *c) {
    int rv = 0;
    char *sci;
    struct {
        uint32_t sid;
        uint32_t sc1i;
        uint32_t sc2i;
    } rand;

    pa_assert(c);

    if (c->rtsp) {
        pa_log_debug("Connection already in progress...");
        return 0;
    }

    c->rtsp = pa_rtsp_client_new(c->core->mainloop, c->host, c->port, "iTunes/7.6.2 (Windows; N;)");

    /* Initialise the AES encryption system. */
    pa_random(c->aes_iv, sizeof(c->aes_iv));
    pa_random(c->aes_key, sizeof(c->aes_key));
    memcpy(c->aes_nv, c->aes_iv, sizeof(c->aes_nv));
    AES_set_encrypt_key(c->aes_key, 128, &c->aes);

    /* Generate random instance ids. */
    pa_random(&rand, sizeof(rand));
    c->sid = pa_sprintf_malloc("%u", rand.sid);
    sci = pa_sprintf_malloc("%08X%08X",rand.sc1i, rand.sc2i);
    pa_rtsp_add_header(c->rtsp, "Client-Instance", sci);
    pa_xfree(sci);

    pa_rtsp_set_callback(c->rtsp, rtsp_cb, c);
    rv = pa_rtsp_connect(c->rtsp);

    return rv;
}

int pa_raop_client_flush(pa_raop_client *c) {
    int rv = 0;

    pa_assert(c);

    pa_rtsp_flush(c->rtsp, c->seq, c->rtptime);

    return rv;
}

int pa_raop_client_teardown(pa_raop_client *c) {
    int rv = 0;

    pa_assert(c);

    /* This should be followed by a STATE_DISCONNECTED event
     * which will take care of cleaning up everything */
    rv = pa_rtsp_teardown(c->rtsp);

    return rv;
}

int pa_raop_client_can_stream(pa_raop_client *c) {
    int rv = 0;

    pa_assert(c);

    if (c->stream_fd != -1)
        rv = 1;

    return rv;
}

int pa_raop_client_handle_timing_packet(pa_raop_client *c, const uint8_t packet[], ssize_t packet_size) {
    uint8_t response[32];
    struct timeval tv;
    uint64_t rci = 0, trs = 0;
    ssize_t written = 0;
    uint8_t plt;
    int rv = 1;
    int i;

    /* RTP v2, seq_num = 0x0007, timestamp = 0. */
    static uint8_t header[] = {
        0x80, 0x00, 0x00, 0x07,
        0x00, 0x00, 0x00, 0x00
    };

    pa_assert(c);

    /* Timing packets are 32 bytes long: 1 x 8 RTP header (no ssrc) + 3 x 8 NTP timestamps. */
    if (packet == NULL || packet_size != 32)
    {
        pa_log_debug("Invalid timing packet: size mismatch.");
        return rv;
    }

    if (packet[0] != 0x80) {
        pa_log_debug("Invalid timing packet: version or control mismatch (0x%02x).", packet[0]);
        return rv;
    }

    rci = timeval_to_ntp(pa_rtclock_get(&tv));
    /* The market bit is always set (see rfc3550) ! */
    plt = packet[1] ^ 0x80;
    switch (plt) {
        case PAYLOAD_TIMING_REQUEST:
            memcpy(response, header, sizeof(header));
            response[1] = 0x80 | PAYLOAD_TIMING_RESPONSE;
            pa_log_debug("%d   %x", response[1], response[1]);
            /* Copying originate timestamp from the incoming request packet. */
            for (i = 8; i < 16; i++)
                response[i] = packet[i + 16];
            /* Set the receive timestamp to reception time. */
            response[16] = (uint8_t) ((rci & 0xff00000000000000) >> 56);
            response[17] = (uint8_t) ((rci & 0x00ff000000000000) >> 48);
            response[18] = (uint8_t) ((rci & 0x0000ff0000000000) >> 40);
            response[19] = (uint8_t) ((rci & 0x000000ff00000000) >> 32);
            response[20] = (uint8_t) ((rci & 0x00000000ff000000) >> 24);
            response[21] = (uint8_t) ((rci & 0x0000000000ff0000) >> 16);
            response[22] = (uint8_t) ((rci & 0x000000000000ff00) >> 8);
            response[23] = (uint8_t)  (rci & 0x00000000000000ff);
            /* Set the transmit timestamp to current time. */
            trs = timeval_to_ntp(pa_rtclock_get(&tv));
            response[24] = (uint8_t) ((trs & 0xff00000000000000) >> 56);
            response[25] = (uint8_t) ((trs & 0x00ff000000000000) >> 48);
            response[26] = (uint8_t) ((trs & 0x0000ff0000000000) >> 40);
            response[27] = (uint8_t) ((trs & 0x000000ff00000000) >> 32);
            response[28] = (uint8_t) ((trs & 0x00000000ff000000) >> 24);
            response[29] = (uint8_t) ((trs & 0x0000000000ff0000) >> 16);
            response[30] = (uint8_t) ((trs & 0x000000000000ff00) >> 8);
            response[31] = (uint8_t)  (trs & 0x00000000000000ff);

            written = pa_loop_write(c->timing_fd, response, sizeof(response), NULL);
            if (written == sizeof(response))
                rv = 0;
            break;
        case PAYLOAD_TIMING_RESPONSE:
        default:
            pa_log_debug("Got an unexpected payload type on timing channel !");
            break;
    }

    return rv;
}

int pa_raop_client_handle_control_packet(pa_raop_client *c, const uint8_t packet[], ssize_t packet_size) {
    uint8_t response[20];
    struct timeval tv;
    uint64_t trs = 0;
    uint32_t tms = 0;
    uint8_t plt;
    int rv = 1;

    /* RTP v2, seq_num = 0x0007, timestamp = 0. */
    static uint8_t header[] = {
        0x80, 0x00, 0x00, 0x07
    };

    pa_assert(c);

    /* No input packet == send a sync one ! */
    if (packet_size <= 0 || packet == NULL)
    {
        memcpy(response, header, sizeof(header));
        if (c->seq == 0)
            response[0] = 0x10 | response[0];
        response[1] = 0x80 | PAYLOAD_SYNCHRONIZATION;
        /* Write current timestamp. */
        tms = c->rtptime;
        response[4] = (uint8_t) ((tms & 0xff000000) >> 24);
        response[5] = (uint8_t) ((tms & 0x00ff0000) >> 16);
        response[6] = (uint8_t) ((tms & 0x0000ff00) >> 8);
        response[7] = (uint8_t)  (tms & 0x000000ff);
        /* Set the transmit timestamp to current time. */
        trs = timeval_to_ntp(pa_rtclock_get(&tv));
        response[8] =  (uint8_t) ((trs & 0xff00000000000000) >> 56);
        response[9] =  (uint8_t) ((trs & 0x00ff000000000000) >> 48);
        response[10] = (uint8_t) ((trs & 0x0000ff0000000000) >> 40);
        response[11] = (uint8_t) ((trs & 0x000000ff00000000) >> 32);
        response[12] = (uint8_t) ((trs & 0x00000000ff000000) >> 24);
        response[13] = (uint8_t) ((trs & 0x0000000000ff0000) >> 16);
        response[14] = (uint8_t) ((trs & 0x000000000000ff00) >> 8);
        response[15] = (uint8_t)  (trs & 0x00000000000000ff);
        /* Write next timestamp. */
        tms += FRAMES_PER_PACKET;
        response[16] = (uint8_t) ((tms & 0xff000000) >> 24);
        response[17] = (uint8_t) ((tms & 0x00ff0000) >> 16);
        response[18] = (uint8_t) ((tms & 0x0000ff00) >> 8);
        response[19] = (uint8_t)  (tms & 0x000000ff);
    } else {
        if (packet[0] != 0x80) {
            pa_log_debug("Invalid timing packet: version or control mismatch (0x%02x).", packet[0]);
            return rv;
        }

        plt = packet[1] ^ 0x80;
        switch (plt) {
            case PAYLOAD_RETRANSMIT_REQUEST:
                /* Packet retransmission not implemented yet... */
            case PAYLOAD_RETRANSMIT_REPLY:
            default:
                pa_log_debug("Got an unexpected payload type on control channel !");
                break;
        }
    }

    return rv;
}

int pa_raop_client_encode_sample(pa_raop_client *c, pa_memchunk *raw, pa_memchunk *encoded) {
    uint16_t len;
    size_t bufmax;
    uint8_t *bp, bpos;
    uint8_t *ibp, *maxibp;
    int size;
    uint8_t *b, *p;
    uint32_t bsize;
    size_t length;
    static uint8_t header[] = {
        0x24, 0x00, 0x00, 0x00,
        0xF0, 0xFF, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    int header_size = sizeof(header);
    int rv = 0;

    pa_assert(c);
    pa_assert(c->stream_fd > 0);
    pa_assert(raw);
    pa_assert(raw->memblock);
    pa_assert(raw->length > 0);
    pa_assert(encoded);

    /* We have to send 4 byte chunks */
    bsize = (int)(raw->length / 4);
    length = bsize * 4;

    /* Leave 16 bytes extra to allow for the ALAC header which is about 55 bits. */
    bufmax = length + header_size + 16;
    pa_memchunk_reset(encoded);
    encoded->memblock = pa_memblock_new(c->core->mempool, bufmax);
    b = pa_memblock_acquire(encoded->memblock);
    memcpy(b, header, header_size);

    /* Now write the actual samples. */
    bp = b + header_size;
    size = bpos = 0;
    bit_writer(&bp,&bpos,&size,1,3); /* channel=1, stereo */
    bit_writer(&bp,&bpos,&size,0,4); /* Unknown */
    bit_writer(&bp,&bpos,&size,0,8); /* Unknown */
    bit_writer(&bp,&bpos,&size,0,4); /* Unknown */
    bit_writer(&bp,&bpos,&size,1,1); /* Hassize */
    bit_writer(&bp,&bpos,&size,0,2); /* Unused */
    bit_writer(&bp,&bpos,&size,1,1); /* Is-not-compressed */

    /* Size of data, integer, big endian. */
    bit_writer(&bp,&bpos,&size,(bsize>>24)&0xff,8);
    bit_writer(&bp,&bpos,&size,(bsize>>16)&0xff,8);
    bit_writer(&bp,&bpos,&size,(bsize>>8)&0xff,8);
    bit_writer(&bp,&bpos,&size,(bsize)&0xff,8);

    ibp = p = pa_memblock_acquire(raw->memblock);
    maxibp = p + raw->length - 4;
    while (ibp <= maxibp) {
        /* Byte swap stereo data. */
        bit_writer(&bp,&bpos,&size,*(ibp+1),8);
        bit_writer(&bp,&bpos,&size,*(ibp+0),8);
        bit_writer(&bp,&bpos,&size,*(ibp+3),8);
        bit_writer(&bp,&bpos,&size,*(ibp+2),8);
        ibp += 4;
        raw->index += 4;
        raw->length -= 4;
    }
    pa_memblock_release(raw->memblock);
    encoded->length = header_size + size;

    /* Store the length (endian swapped: make this better). */
    len = size + header_size - 4;
    *(b + 2) = len >> 8;
    *(b + 3) = len & 0xff;

    /* Encrypt our data. */
    aes_encrypt(c, (b + header_size), size);

    /* We're done with the chunk. */
    pa_memblock_release(encoded->memblock);

    return rv;
}

int pa_raop_client_set_volume(pa_raop_client *c, pa_volume_t volume) {
    char *param;
    int rv = 0;
    double db;

    pa_assert(c);

    db = pa_sw_volume_to_dB(volume);
    if (db < VOLUME_MIN)
        db = VOLUME_MIN;
    else if (db > VOLUME_MAX)
        db = VOLUME_MAX;

    param = pa_sprintf_malloc("volume: %0.6f\r\n", db);

    /* We just hit and hope, cannot wait for the callback. */
    rv = pa_rtsp_setparameter(c->rtsp, param);
    pa_xfree(param);

    return rv;
}

void pa_raop_client_set_setup_callback(pa_raop_client *c, pa_raop_client_setup_cb_t callback, void *userdata) {
    pa_assert(c);

    c->setup_callback = callback;
    c->setup_userdata = userdata;
}

void pa_raop_client_set_record_callback(pa_raop_client *c, pa_raop_client_record_cb_t callback, void *userdata) {
    pa_assert(c);

    c->record_callback = callback;
    c->record_userdata = userdata;
}

void pa_raop_client_set_disconnected_callback(pa_raop_client *c, pa_raop_client_disconnected_cb_t callback, void *userdata) {
    pa_assert(c);

    c->disconnected_callback = callback;
    c->disconnected_userdata = userdata;
}

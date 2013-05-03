#ifndef fooraopclientfoo
#define fooraopclientfoo

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

#include <pulse/volume.h>

#include <pulsecore/core.h>
#include <pulsecore/memchunk.h>

typedef struct pa_raop_client pa_raop_client;

pa_raop_client* pa_raop_client_new(pa_core *core, const char *host);
void pa_raop_client_free(pa_raop_client *c);

int pa_raop_client_connect(pa_raop_client *c);
int pa_raop_client_flush(pa_raop_client *c);
int pa_raop_client_teardown(pa_raop_client *c);

int pa_raop_client_can_stream(pa_raop_client *c);

int pa_raop_client_handle_timing_packet(pa_raop_client *c, const uint8_t packet[], ssize_t packet_size);
int pa_raop_client_handle_control_packet(pa_raop_client *c, const uint8_t packet[], ssize_t packet_size);
int pa_raop_client_synchronize_timestamps(pa_raop_client *c, uint32_t stamp);
int pa_raop_client_encode_sample(pa_raop_client *c, pa_memchunk *raw, pa_memchunk *encoded);

int pa_raop_client_set_volume(pa_raop_client *c, pa_volume_t volume);

typedef void (*pa_raop_client_setup_cb_t)(int control_fd, int timing_fd, void *userdata);
void pa_raop_client_set_setup_callback(pa_raop_client *c, pa_raop_client_setup_cb_t callback, void *userdata);

typedef void (*pa_raop_client_record_cb_t)(void *userdata);
void pa_raop_client_set_record_callback(pa_raop_client *c, pa_raop_client_record_cb_t callback, void *userdata);

typedef void (*pa_raop_client_disconnected_cb_t)(void *userdata);
void pa_raop_client_set_disconnected_callback(pa_raop_client *c, pa_raop_client_disconnected_cb_t callback, void *userdata);

#endif

/* NBD client library in userspace
 * WARNING: THIS FILE IS GENERATED FROM
 * generator/generator
 * ANY CHANGES YOU MAKE TO THIS FILE WILL BE LOST.
 *
 * Copyright (C) 2013-2019 Red Hat Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

package libnbd

/*
#cgo pkg-config: libnbd

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libnbd.h"
#include "wrappers.h"

int
_nbd_set_debug_wrapper (struct error *err,
        struct nbd_handle *h, bool debug)
{
  int ret;

  ret = nbd_set_debug (h, debug);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_get_debug_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_get_debug (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_set_debug_callback_wrapper (struct error *err,
        struct nbd_handle *h, nbd_debug_callback debug_callback)
{
  int ret;

  ret = nbd_set_debug_callback (h, debug_callback);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_clear_debug_callback_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_clear_debug_callback (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_set_handle_name_wrapper (struct error *err,
        struct nbd_handle *h, const char *handle_name)
{
  int ret;

  ret = nbd_set_handle_name (h, handle_name);
  if (ret == -1)
    save_error (err);
  return ret;
}

char *
_nbd_get_handle_name_wrapper (struct error *err,
        struct nbd_handle *h)
{
  char * ret;

  ret = nbd_get_handle_name (h);
  if (ret == NULL)
    save_error (err);
  return ret;
}

int
_nbd_set_export_name_wrapper (struct error *err,
        struct nbd_handle *h, const char *export_name)
{
  int ret;

  ret = nbd_set_export_name (h, export_name);
  if (ret == -1)
    save_error (err);
  return ret;
}

char *
_nbd_get_export_name_wrapper (struct error *err,
        struct nbd_handle *h)
{
  char * ret;

  ret = nbd_get_export_name (h);
  if (ret == NULL)
    save_error (err);
  return ret;
}

int
_nbd_set_tls_wrapper (struct error *err,
        struct nbd_handle *h, int tls)
{
  int ret;

  ret = nbd_set_tls (h, tls);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_get_tls_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_get_tls (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_get_tls_negotiated_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_get_tls_negotiated (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_set_tls_certificates_wrapper (struct error *err,
        struct nbd_handle *h, const char *dir)
{
  int ret;

  ret = nbd_set_tls_certificates (h, dir);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_set_tls_verify_peer_wrapper (struct error *err,
        struct nbd_handle *h, bool verify)
{
  int ret;

  ret = nbd_set_tls_verify_peer (h, verify);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_get_tls_verify_peer_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_get_tls_verify_peer (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_set_tls_username_wrapper (struct error *err,
        struct nbd_handle *h, const char *username)
{
  int ret;

  ret = nbd_set_tls_username (h, username);
  if (ret == -1)
    save_error (err);
  return ret;
}

char *
_nbd_get_tls_username_wrapper (struct error *err,
        struct nbd_handle *h)
{
  char * ret;

  ret = nbd_get_tls_username (h);
  if (ret == NULL)
    save_error (err);
  return ret;
}

int
_nbd_set_tls_psk_file_wrapper (struct error *err,
        struct nbd_handle *h, const char *filename)
{
  int ret;

  ret = nbd_set_tls_psk_file (h, filename);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_set_request_structured_replies_wrapper (struct error *err,
        struct nbd_handle *h, bool request)
{
  int ret;

  ret = nbd_set_request_structured_replies (h, request);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_get_request_structured_replies_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_get_request_structured_replies (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_get_structured_replies_negotiated_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_get_structured_replies_negotiated (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_set_handshake_flags_wrapper (struct error *err,
        struct nbd_handle *h, uint32_t flags)
{
  int ret;

  ret = nbd_set_handshake_flags (h, flags);
  if (ret == -1)
    save_error (err);
  return ret;
}

unsigned
_nbd_get_handshake_flags_wrapper (struct error *err,
        struct nbd_handle *h)
{
  unsigned ret;

  ret = nbd_get_handshake_flags (h);
  return ret;
}

int
_nbd_add_meta_context_wrapper (struct error *err,
        struct nbd_handle *h, const char *name)
{
  int ret;

  ret = nbd_add_meta_context (h, name);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_set_uri_allow_transports_wrapper (struct error *err,
        struct nbd_handle *h, uint32_t mask)
{
  int ret;

  ret = nbd_set_uri_allow_transports (h, mask);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_set_uri_allow_tls_wrapper (struct error *err,
        struct nbd_handle *h, int tls)
{
  int ret;

  ret = nbd_set_uri_allow_tls (h, tls);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_set_uri_allow_local_file_wrapper (struct error *err,
        struct nbd_handle *h, bool allow)
{
  int ret;

  ret = nbd_set_uri_allow_local_file (h, allow);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_connect_uri_wrapper (struct error *err,
        struct nbd_handle *h, const char *uri)
{
  int ret;

  ret = nbd_connect_uri (h, uri);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_connect_unix_wrapper (struct error *err,
        struct nbd_handle *h, const char *unixsocket)
{
  int ret;

  ret = nbd_connect_unix (h, unixsocket);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_connect_vsock_wrapper (struct error *err,
        struct nbd_handle *h, uint32_t cid, uint32_t port)
{
  int ret;

  ret = nbd_connect_vsock (h, cid, port);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_connect_tcp_wrapper (struct error *err,
        struct nbd_handle *h, const char *hostname, const char *port)
{
  int ret;

  ret = nbd_connect_tcp (h, hostname, port);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_connect_socket_wrapper (struct error *err,
        struct nbd_handle *h, int sock)
{
  int ret;

  ret = nbd_connect_socket (h, sock);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_connect_command_wrapper (struct error *err,
        struct nbd_handle *h, char **argv)
{
  int ret;

  ret = nbd_connect_command (h, argv);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_connect_systemd_socket_activation_wrapper (struct error *err,
        struct nbd_handle *h, char **argv)
{
  int ret;

  ret = nbd_connect_systemd_socket_activation (h, argv);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_is_read_only_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_is_read_only (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_can_flush_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_can_flush (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_can_fua_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_can_fua (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_is_rotational_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_is_rotational (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_can_trim_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_can_trim (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_can_zero_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_can_zero (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_can_fast_zero_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_can_fast_zero (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_can_df_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_can_df (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_can_multi_conn_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_can_multi_conn (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_can_cache_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_can_cache (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_can_meta_context_wrapper (struct error *err,
        struct nbd_handle *h, const char *metacontext)
{
  int ret;

  ret = nbd_can_meta_context (h, metacontext);
  if (ret == -1)
    save_error (err);
  return ret;
}

const char *
_nbd_get_protocol_wrapper (struct error *err,
        struct nbd_handle *h)
{
  const char * ret;

  ret = nbd_get_protocol (h);
  if (ret == NULL)
    save_error (err);
  return ret;
}

int64_t
_nbd_get_size_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int64_t ret;

  ret = nbd_get_size (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_pread_wrapper (struct error *err,
        struct nbd_handle *h, void *buf, size_t count, uint64_t offset,
        uint32_t flags)
{
  int ret;

  ret = nbd_pread (h, buf, count, offset, flags);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_pread_structured_wrapper (struct error *err,
        struct nbd_handle *h, void *buf, size_t count, uint64_t offset,
        nbd_chunk_callback chunk_callback, uint32_t flags)
{
  int ret;

  ret = nbd_pread_structured (h, buf, count, offset, chunk_callback, flags);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_pwrite_wrapper (struct error *err,
        struct nbd_handle *h, const void *buf, size_t count,
        uint64_t offset, uint32_t flags)
{
  int ret;

  ret = nbd_pwrite (h, buf, count, offset, flags);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_shutdown_wrapper (struct error *err,
        struct nbd_handle *h, uint32_t flags)
{
  int ret;

  ret = nbd_shutdown (h, flags);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_flush_wrapper (struct error *err,
        struct nbd_handle *h, uint32_t flags)
{
  int ret;

  ret = nbd_flush (h, flags);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_trim_wrapper (struct error *err,
        struct nbd_handle *h, uint64_t count, uint64_t offset,
        uint32_t flags)
{
  int ret;

  ret = nbd_trim (h, count, offset, flags);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_cache_wrapper (struct error *err,
        struct nbd_handle *h, uint64_t count, uint64_t offset,
        uint32_t flags)
{
  int ret;

  ret = nbd_cache (h, count, offset, flags);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_zero_wrapper (struct error *err,
        struct nbd_handle *h, uint64_t count, uint64_t offset,
        uint32_t flags)
{
  int ret;

  ret = nbd_zero (h, count, offset, flags);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_block_status_wrapper (struct error *err,
        struct nbd_handle *h, uint64_t count, uint64_t offset,
        nbd_extent_callback extent_callback, uint32_t flags)
{
  int ret;

  ret = nbd_block_status (h, count, offset, extent_callback, flags);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_poll_wrapper (struct error *err,
        struct nbd_handle *h, int timeout)
{
  int ret;

  ret = nbd_poll (h, timeout);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_aio_connect_wrapper (struct error *err,
        struct nbd_handle *h, const struct sockaddr *addr,
        socklen_t addrlen)
{
  int ret;

  ret = nbd_aio_connect (h, addr, addrlen);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_aio_connect_uri_wrapper (struct error *err,
        struct nbd_handle *h, const char *uri)
{
  int ret;

  ret = nbd_aio_connect_uri (h, uri);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_aio_connect_unix_wrapper (struct error *err,
        struct nbd_handle *h, const char *unixsocket)
{
  int ret;

  ret = nbd_aio_connect_unix (h, unixsocket);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_aio_connect_vsock_wrapper (struct error *err,
        struct nbd_handle *h, uint32_t cid, uint32_t port)
{
  int ret;

  ret = nbd_aio_connect_vsock (h, cid, port);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_aio_connect_tcp_wrapper (struct error *err,
        struct nbd_handle *h, const char *hostname, const char *port)
{
  int ret;

  ret = nbd_aio_connect_tcp (h, hostname, port);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_aio_connect_socket_wrapper (struct error *err,
        struct nbd_handle *h, int sock)
{
  int ret;

  ret = nbd_aio_connect_socket (h, sock);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_aio_connect_command_wrapper (struct error *err,
        struct nbd_handle *h, char **argv)
{
  int ret;

  ret = nbd_aio_connect_command (h, argv);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_aio_connect_systemd_socket_activation_wrapper (struct error *err,
        struct nbd_handle *h, char **argv)
{
  int ret;

  ret = nbd_aio_connect_systemd_socket_activation (h, argv);
  if (ret == -1)
    save_error (err);
  return ret;
}

int64_t
_nbd_aio_pread_wrapper (struct error *err,
        struct nbd_handle *h, void *buf, size_t count, uint64_t offset,
        nbd_completion_callback completion_callback, uint32_t flags)
{
  int64_t ret;

  ret = nbd_aio_pread (h, buf, count, offset, completion_callback, flags);
  if (ret == -1)
    save_error (err);
  return ret;
}

int64_t
_nbd_aio_pread_structured_wrapper (struct error *err,
        struct nbd_handle *h, void *buf, size_t count, uint64_t offset,
        nbd_chunk_callback chunk_callback,
        nbd_completion_callback completion_callback, uint32_t flags)
{
  int64_t ret;

  ret = nbd_aio_pread_structured (h, buf, count, offset, chunk_callback,
                                  completion_callback, flags);
  if (ret == -1)
    save_error (err);
  return ret;
}

int64_t
_nbd_aio_pwrite_wrapper (struct error *err,
        struct nbd_handle *h, const void *buf, size_t count,
        uint64_t offset, nbd_completion_callback completion_callback,
        uint32_t flags)
{
  int64_t ret;

  ret = nbd_aio_pwrite (h, buf, count, offset, completion_callback, flags);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_aio_disconnect_wrapper (struct error *err,
        struct nbd_handle *h, uint32_t flags)
{
  int ret;

  ret = nbd_aio_disconnect (h, flags);
  if (ret == -1)
    save_error (err);
  return ret;
}

int64_t
_nbd_aio_flush_wrapper (struct error *err,
        struct nbd_handle *h, nbd_completion_callback completion_callback,
        uint32_t flags)
{
  int64_t ret;

  ret = nbd_aio_flush (h, completion_callback, flags);
  if (ret == -1)
    save_error (err);
  return ret;
}

int64_t
_nbd_aio_trim_wrapper (struct error *err,
        struct nbd_handle *h, uint64_t count, uint64_t offset,
        nbd_completion_callback completion_callback, uint32_t flags)
{
  int64_t ret;

  ret = nbd_aio_trim (h, count, offset, completion_callback, flags);
  if (ret == -1)
    save_error (err);
  return ret;
}

int64_t
_nbd_aio_cache_wrapper (struct error *err,
        struct nbd_handle *h, uint64_t count, uint64_t offset,
        nbd_completion_callback completion_callback, uint32_t flags)
{
  int64_t ret;

  ret = nbd_aio_cache (h, count, offset, completion_callback, flags);
  if (ret == -1)
    save_error (err);
  return ret;
}

int64_t
_nbd_aio_zero_wrapper (struct error *err,
        struct nbd_handle *h, uint64_t count, uint64_t offset,
        nbd_completion_callback completion_callback, uint32_t flags)
{
  int64_t ret;

  ret = nbd_aio_zero (h, count, offset, completion_callback, flags);
  if (ret == -1)
    save_error (err);
  return ret;
}

int64_t
_nbd_aio_block_status_wrapper (struct error *err,
        struct nbd_handle *h, uint64_t count, uint64_t offset,
        nbd_extent_callback extent_callback,
        nbd_completion_callback completion_callback, uint32_t flags)
{
  int64_t ret;

  ret = nbd_aio_block_status (h, count, offset, extent_callback,
                              completion_callback, flags);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_aio_get_fd_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_aio_get_fd (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

unsigned
_nbd_aio_get_direction_wrapper (struct error *err,
        struct nbd_handle *h)
{
  unsigned ret;

  ret = nbd_aio_get_direction (h);
  return ret;
}

int
_nbd_aio_notify_read_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_aio_notify_read (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_aio_notify_write_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_aio_notify_write (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_aio_is_created_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_aio_is_created (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_aio_is_connecting_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_aio_is_connecting (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_aio_is_ready_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_aio_is_ready (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_aio_is_processing_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_aio_is_processing (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_aio_is_dead_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_aio_is_dead (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_aio_is_closed_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_aio_is_closed (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_aio_command_completed_wrapper (struct error *err,
        struct nbd_handle *h, uint64_t cookie)
{
  int ret;

  ret = nbd_aio_command_completed (h, cookie);
  if (ret == -1)
    save_error (err);
  return ret;
}

int64_t
_nbd_aio_peek_command_completed_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int64_t ret;

  ret = nbd_aio_peek_command_completed (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_aio_in_flight_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_aio_in_flight (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

const char *
_nbd_connection_state_wrapper (struct error *err,
        struct nbd_handle *h)
{
  const char * ret;

  ret = nbd_connection_state (h);
  if (ret == NULL)
    save_error (err);
  return ret;
}

const char *
_nbd_get_package_name_wrapper (struct error *err,
        struct nbd_handle *h)
{
  const char * ret;

  ret = nbd_get_package_name (h);
  if (ret == NULL)
    save_error (err);
  return ret;
}

const char *
_nbd_get_version_wrapper (struct error *err,
        struct nbd_handle *h)
{
  const char * ret;

  ret = nbd_get_version (h);
  if (ret == NULL)
    save_error (err);
  return ret;
}

int
_nbd_kill_subprocess_wrapper (struct error *err,
        struct nbd_handle *h, int signum)
{
  int ret;

  ret = nbd_kill_subprocess (h, signum);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_supports_tls_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_supports_tls (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_supports_uri_wrapper (struct error *err,
        struct nbd_handle *h)
{
  int ret;

  ret = nbd_supports_uri (h);
  if (ret == -1)
    save_error (err);
  return ret;
}

int
_nbd_chunk_callback_wrapper (void *user_data, const void *subbuf,
                             size_t count, uint64_t offset, unsigned status,
                             int *error)
{
  return chunk_callback ((long)user_data, subbuf, count, offset, status, error);
}

void
_nbd_chunk_callback_free (void *user_data)
{
  extern void freeCallbackId (long);
  freeCallbackId ((long)user_data);
}

int
_nbd_completion_callback_wrapper (void *user_data, int *error)
{
  return completion_callback ((long)user_data, error);
}

void
_nbd_completion_callback_free (void *user_data)
{
  extern void freeCallbackId (long);
  freeCallbackId ((long)user_data);
}

int
_nbd_debug_callback_wrapper (void *user_data, const char *context,
                             const char *msg)
{
  return debug_callback ((long)user_data, context, msg);
}

void
_nbd_debug_callback_free (void *user_data)
{
  extern void freeCallbackId (long);
  freeCallbackId ((long)user_data);
}

int
_nbd_extent_callback_wrapper (void *user_data, const char *metacontext,
                              uint64_t offset, uint32_t *entries,
                              size_t nr_entries, int *error)
{
  return extent_callback ((long)user_data, metacontext, offset, entries, nr_entries, error);
}

void
_nbd_extent_callback_free (void *user_data)
{
  extern void freeCallbackId (long);
  freeCallbackId ((long)user_data);
}

// There must be no blank line between end comment and import!
// https://github.com/golang/go/issues/9733
*/
import "C"

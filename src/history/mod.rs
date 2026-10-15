pub mod rpc;
pub mod supervisor;
pub mod worker;

pub fn socket_buffers(fd: std::os::fd::RawFd) -> crate::Result<()> {
    let size: libc::c_int = 64 * 1024;
    for option in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
        // SAFETY: fd is an open Unix socket and size points to a live c_int.
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&size as *const libc::c_int).cast(),
                std::mem::size_of_val(&size) as libc::socklen_t,
            )
        };
        crate::ensure!(
            result == 0,
            "WorkerProtocol: cannot configure socket buffer: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

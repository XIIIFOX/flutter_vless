"""Enforce final mandatory Darwin outbound interface binding on every return.

Only a disposable, pinned Core copy may be passed by the composing caller.
All caller TCP/custom settings retain their original code and values. Interface
lookup/setsockopt failures remain BindError, which the system dialer propagates.
"""

PATH = 'transport/internet/sockopt_darwin.go'

BEFORE = '''func applyOutboundSocketOptions(network string, address string, fd uintptr, config *SocketConfig) error {
	if isTCPSocket(network) {
		tfo := config.ParseTFOValue()
		if tfo > 0 {
			tfo = TCP_FASTOPEN_CLIENT
		}
		if tfo >= 0 {
			if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN, tfo); err != nil {
				return err
			}
		}

		if config.TcpKeepAliveIdle > 0 || config.TcpKeepAliveInterval > 0 {
			if config.TcpKeepAliveIdle > 0 {
				if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPALIVE, int(config.TcpKeepAliveIdle)); err != nil {
					return errors.New("failed to set TCP_KEEPALIVE", err)
				}
			}
			if config.TcpKeepAliveInterval > 0 {
				if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, sysTCP_KEEPINTVL, int(config.TcpKeepAliveInterval)); err != nil {
					return errors.New("failed to set TCP_KEEPINTVL", err)
				}
			}
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_KEEPALIVE, 1); err != nil {
				return errors.New("failed to set SO_KEEPALIVE", err)
			}
		} else if config.TcpKeepAliveInterval < 0 || config.TcpKeepAliveIdle < 0 {
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_KEEPALIVE, 0); err != nil {
				return errors.New("failed to unset SO_KEEPALIVE", err)
			}
		}
	}

	if config.Interface != "" {
		iface, err := net.InterfaceByName(config.Interface)
		if err != nil {
			return NewBindError(errors.New("failed to get interface ", config.Interface).Base(err))
		}
		if network == "tcp6" || network == "udp6" {
			if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, iface.Index); err != nil {
				return NewBindError(errors.New("failed to set IPV6_BOUND_IF").Base(err))
			}
		} else {
			if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, iface.Index); err != nil {
				return NewBindError(errors.New("failed to set IP_BOUND_IF").Base(err))
			}
		}
	}
'''

AFTER = '''// Referenced by the opt-in mobile ABI; an unpatched Core cannot compile it.
const DarwinInterfaceBindingCapability = 1

func applyOutboundSocketOptions(network string, address string, fd uintptr, config *SocketConfig) (err error) {
	// Optional/custom settings may fail or change binding. Enforce the chosen
	// interface on every return, and never hide a failed final mandatory bind.
	defer func() {
		if config.Interface == "" { return }
		iface, bindErr := net.InterfaceByName(config.Interface)
		if bindErr != nil {
			err = NewBindError(errors.New("failed to get interface ", config.Interface).Base(bindErr))
			return
		}
		if network == "tcp6" || network == "udp6" {
			if bindErr := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, iface.Index); bindErr != nil {
				err = NewBindError(errors.New("failed to set IPV6_BOUND_IF").Base(bindErr))
			}
		} else {
			if bindErr := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, iface.Index); bindErr != nil {
				err = NewBindError(errors.New("failed to set IP_BOUND_IF").Base(bindErr))
			}
		}
	}()

	if isTCPSocket(network) {
		tfo := config.ParseTFOValue()
		if tfo > 0 {
			tfo = TCP_FASTOPEN_CLIENT
		}
		if tfo >= 0 {
			if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN, tfo); err != nil {
				return err
			}
		}

		if config.TcpKeepAliveIdle > 0 || config.TcpKeepAliveInterval > 0 {
			if config.TcpKeepAliveIdle > 0 {
				if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPALIVE, int(config.TcpKeepAliveIdle)); err != nil {
					return errors.New("failed to set TCP_KEEPALIVE", err)
				}
			}
			if config.TcpKeepAliveInterval > 0 {
				if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, sysTCP_KEEPINTVL, int(config.TcpKeepAliveInterval)); err != nil {
					return errors.New("failed to set TCP_KEEPINTVL", err)
				}
			}
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_KEEPALIVE, 1); err != nil {
				return errors.New("failed to set SO_KEEPALIVE", err)
			}
		} else if config.TcpKeepAliveInterval < 0 || config.TcpKeepAliveIdle < 0 {
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_KEEPALIVE, 0); err != nil {
				return errors.New("failed to unset SO_KEEPALIVE", err)
			}
		}
	}

'''


def apply(root, replace):
    path = root / PATH
    if path.is_symlink() or not path.is_file():
        raise ValueError('Darwin interface source must be a real file')
    if path.read_text().count(BEFORE) != 1:
        raise ValueError('Pinned Darwin interface replacement boundary changed')
    replace(PATH, BEFORE, AFTER)

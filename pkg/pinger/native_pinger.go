package pinger

type NativePinger struct {
}

func (p *NativePinger) Ping(hostname string) error {
	return nil
}

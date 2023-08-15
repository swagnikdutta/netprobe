package pinger

type Pinger interface {
	Ping(hostname string) error
}

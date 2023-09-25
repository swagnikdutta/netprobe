package ping

import (
	"net"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	dialer "github.com/swagnikdutta/netprobe/pkg/dialer/mocks"
	local "github.com/swagnikdutta/netprobe/pkg/resolver/local/mocks"
	"go.uber.org/mock/gomock"
)

type MockConn struct {
	net.Conn
}

func (m *MockConn) Close() error {
	return nil
}

func (m *MockConn) Write(b []byte) (n int, err error) {
	return 0, nil
}

func (m *MockConn) Read(b []byte) (n int, err error) {
	fakeEchoResponse := []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	}
	copy(b, fakeEchoResponse)
	return len(b), nil
}

func TestPing_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockResolver := local.NewMockResolver(ctrl)
	mockDialer := dialer.NewMockNetworkDialer(ctrl)
	mockConn := new(MockConn)

	host := "test-host.com"
	fakeSourceIP := net.IP{127, 0, 0, 1}
	fakeDestIP := net.IP{127, 0, 0, 1}

	pinger := &Pinger{
		count:    3,
		resolver: mockResolver,
		dialer:   mockDialer,
	}

	mockResolver.EXPECT().ResolveSource().Return(fakeSourceIP, nil)
	mockResolver.EXPECT().ResolveDestination(host).Return(fakeDestIP, nil)
	mockDialer.EXPECT().Dial("ip4:icmp", "127.0.0.1").Times(int(pinger.count)).
		Return(mockConn, nil)

	err := pinger.Ping(host)
	assert.Nil(t, err)
}

func TestPing_SourceAddressResolutionError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockResolver := local.NewMockResolver(ctrl)
	mockDialer := dialer.NewMockNetworkDialer(ctrl)

	host := "test-host.com"
	addrNotFoundErr := errors.New("source-not-found")

	pinger := &Pinger{
		count:    3,
		resolver: mockResolver,
		dialer:   mockDialer,
	}

	mockResolver.EXPECT().ResolveSource().Return(nil, addrNotFoundErr)

	errGot := pinger.Ping(host)
	errExp := errors.Wrapf(addrNotFoundErr, "error resolving source address")
	assert.EqualError(t, errGot, errExp.Error())
}

func TestPing_DestinationAddressResolutionError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockResolver := local.NewMockResolver(ctrl)
	mockDialer := dialer.NewMockNetworkDialer(ctrl)

	host := "test-host.com"
	fakeSourceIP := net.IP{127, 0, 0, 1}
	addrNotFoundErr := errors.New("dest-not-found")

	pinger := &Pinger{
		count:    3,
		resolver: mockResolver,
		dialer:   mockDialer,
	}

	mockResolver.EXPECT().ResolveSource().Return(fakeSourceIP, nil)
	mockResolver.EXPECT().ResolveDestination(host).Return(nil, addrNotFoundErr)

	errGot := pinger.Ping(host)
	errExp := errors.Wrapf(addrNotFoundErr, "error resolving destination address")
	assert.EqualError(t, errGot, errExp.Error())
}

func TestPing_DialErrorOnLastPacket(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockResolver := local.NewMockResolver(ctrl)
	mockDialer := dialer.NewMockNetworkDialer(ctrl)
	mockConn := new(MockConn)

	host := "test-host.com"
	fakeSourceIP := net.IP{127, 0, 0, 1}
	fakeDestIP := net.IP{127, 0, 0, 1}
	dialErr := errors.New("network-dial-error")

	pinger := &Pinger{
		count:    3,
		resolver: mockResolver,
		dialer:   mockDialer,
	}

	mockResolver.EXPECT().ResolveSource().Return(fakeSourceIP, nil)
	mockResolver.EXPECT().ResolveDestination(host).Return(fakeDestIP, nil)
	mockDialer.EXPECT().Dial("ip4:icmp", "127.0.0.1").Times(int(pinger.count)-1).
		Return(mockConn, nil)
	mockDialer.EXPECT().Dial("ip4:icmp", "127.0.0.1").Return(nil, dialErr)

	errGot := pinger.Ping(host)
	errExp := errors.Wrapf(dialErr, "error eshtablishing connection with %s", host)
	assert.EqualError(t, errGot, errExp.Error())
}

package hack

import (
	"context"
	"github.com/hashicorp/go-getter"
	"gopkg.in/ns3777k/go-shodan.v3/shodan"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
)

type Client struct {
	cli *shodan.Client
	get *getter.Client
}

func New(client *http.Client) *Client {
	// Get the pwd
	pwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Error getting wd: %s", err)
	}

	opts := []getter.ClientOption{}

	// Build the client
	get := &getter.Client{
		Ctx:     context.Background(),
		Pwd:     pwd,
		Options: opts,
	}
	return &Client{
		cli: shodan.NewEnvClient(client),
		get: get,
	}
}

func (c *Client) GetDNS(ctx context.Context, hostNames ...string) (map[string]*net.IP, error) {
	names, err := c.cli.GetDNSResolve(ctx, hostNames)
	if err != nil {
		return nil, err
	}
	return names, nil
}

func (c *Client) GetHostsByASN(ctx context.Context, data chan *shodan.HostData, asns ...string) error {
	return c.cli.GetBannersByASN(ctx, asns, data)
}

func (c *Client) GetHostsByPort(ctx context.Context, data chan *shodan.HostData, ports ...int) error {
	return c.cli.GetBannersByPorts(ctx, ports, data)
}

func (c *Client) GetHostsByCountries(ctx context.Context, data chan *shodan.HostData, countries ...string) error {
	return c.cli.GetBannersByCountries(ctx, countries, data)
}

func (c *Client) Headers(ctx context.Context) (map[string]string, error) {
	return c.cli.GetHTTPHeaders(ctx)
}

func (c *Client) GetMyIP(ctx context.Context) (net.IP, error) {
	return c.cli.GetMyIP(ctx)
}

func (c *Client) ReverseDNS(ctx context.Context, ipStrs ...string) (map[string]*[]string, error) {
	var ips []net.IP
	for _, i := range ipStrs {
		ips = append(ips, net.ParseIP(i))
	}
	names, err := c.cli.GetDNSReverse(ctx, ips)
	if err != nil {
		return nil, err
	}
	return names, nil
}

func (c *Client) Debug() {
	c.cli.SetDebug(true)
}

func (cli *Client) DownloadAny(ctx context.Context, url, dest string) {
	ct, cancel := context.WithCancel(ctx)
	cli.get.Mode = getter.ClientModeAny
	cli.get.Src = url
	cli.get.Dst = dest
	cli.get.Ctx = ct
	wg := sync.WaitGroup{}
	wg.Add(1)
	errChan := make(chan error, 2)
	go func() {
		defer wg.Done()
		defer cancel()
		if err := cli.get.Get(); err != nil {
			errChan <- err
		}
	}()

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt)

	select {
	case sig := <-c:
		signal.Reset(os.Interrupt)
		cancel()
		wg.Wait()
		log.Printf("signal %v", sig)
	case <-ctx.Done():
		wg.Wait()
		log.Printf("success!")
	case err := <-errChan:
		wg.Wait()
		log.Fatalf("Error downloading: %s", err)
	}
}

func (cli *Client) DownloadFile(ctx context.Context, url, dest string) {
	ct, cancel := context.WithCancel(ctx)
	cli.get.Mode = getter.ClientModeFile
	cli.get.Src = url
	cli.get.Dst = dest
	cli.get.Ctx = ct
	wg := sync.WaitGroup{}
	wg.Add(1)
	errChan := make(chan error, 2)
	go func() {
		defer wg.Done()
		defer cancel()
		if err := cli.get.Get(); err != nil {
			errChan <- err
		}
	}()

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt)

	select {
	case sig := <-c:
		signal.Reset(os.Interrupt)
		cancel()
		wg.Wait()
		log.Printf("signal %v", sig)
	case <-ctx.Done():
		wg.Wait()
		log.Printf("success!")
	case err := <-errChan:
		wg.Wait()
		log.Fatalf("Error downloading: %s", err)
	}
}

func (cli *Client) DownloadDir(ctx context.Context, url, dest string) {
	ct, cancel := context.WithCancel(ctx)
	cli.get.Mode = getter.ClientModeDir
	cli.get.Src = url
	cli.get.Dst = dest
	cli.get.Ctx = ct
	wg := sync.WaitGroup{}
	wg.Add(1)
	errChan := make(chan error, 2)
	go func() {
		defer wg.Done()
		defer cancel()
		if err := cli.get.Get(); err != nil {
			errChan <- err
		}
	}()

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt)

	select {
	case sig := <-c:
		signal.Reset(os.Interrupt)
		cancel()
		wg.Wait()
		log.Printf("signal %v", sig)
	case <-ctx.Done():
		wg.Wait()
		log.Printf("success!")
	case err := <-errChan:
		wg.Wait()
		log.Fatalf("Error downloading: %s", err)
	}
}

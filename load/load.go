package load

import (
	"context"
	"github.com/hashicorp/go-getter"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
)

type Client struct {
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
		get: get,
	}
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

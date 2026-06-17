package handlers

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type failingWriter struct{}

func (f failingWriter) Write(_ []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

type failingWriteCloser struct {
	closeCount atomic.Int32
}

func (f *failingWriteCloser) Write(_ []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func (f *failingWriteCloser) Close() error {
	f.closeCount.Add(1)
	return nil
}

type trackingWriteCloser struct {
	bytes.Buffer
	closeCount atomic.Int32
}

func (w *trackingWriteCloser) Close() error {
	w.closeCount.Add(1)
	return nil
}

type concurrentDetectWriter struct {
	active        atomic.Int32
	maxActive     atomic.Int32
	concurrencyCh chan struct{}
}

func (w *concurrentDetectWriter) Write(p []byte) (int, error) {
	active := w.active.Add(1)
	for {
		currentMax := w.maxActive.Load()
		if active <= currentMax || w.maxActive.CompareAndSwap(currentMax, active) {
			break
		}
	}
	if active > 1 && w.concurrencyCh != nil {
		select {
		case w.concurrencyCh <- struct{}{}:
		default:
		}
	}
	time.Sleep(10 * time.Millisecond)
	w.active.Add(-1)
	return len(p), nil
}

func TestStreamHubWriteToIPReturnsUnavailableWithoutRegisteredStream(t *testing.T) {
	hub := newStreamHub()

	err := hub.writeToIP(123, []byte("payload"))
	if !errors.Is(err, errStreamUnavailable) {
		t.Fatalf("expected errStreamUnavailable, got %v", err)
	}
}

func TestStreamHubWriteToIPRemovesStaleStreamOnWriteFailure(t *testing.T) {
	hub := newStreamHub()
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443}
	writer := &failingWriteCloser{}
	hub.registerSession(remoteAddr, "", 123, &sessionStream{
		remoteAddr: remoteAddr.String(),
		rawWriter:  writer,
		rawCloser:  writer,
	})

	err := hub.writeToIP(123, []byte("payload"))
	if err == nil {
		t.Fatalf("expected write failure")
	}
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("expected wrapped io.ErrClosedPipe, got %v", err)
	}

	err = hub.writeToIP(123, []byte("payload"))
	if !errors.Is(err, errStreamUnavailable) {
		t.Fatalf("expected stale stream removal after write failure, got %v", err)
	}
	if writer.closeCount.Load() != 1 {
		t.Fatalf("expected broken session to be closed once, got %d", writer.closeCount.Load())
	}
}

func TestStreamHubRegisterSessionPreservesClosableWriter(t *testing.T) {
	hub := newStreamHub()
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443}
	oldWriter := &trackingWriteCloser{}
	newWriter := &trackingWriteCloser{}

	hub.registerSession(remoteAddr, "", 123, &sessionStream{
		remoteAddr: remoteAddr.String(),
		rawWriter:  oldWriter,
		rawCloser:  oldWriter,
	})
	hub.registerSession(remoteAddr, "", 123, &sessionStream{
		remoteAddr: remoteAddr.String(),
		rawWriter:  newWriter,
		rawCloser:  newWriter,
	})

	if oldWriter.closeCount.Load() != 1 {
		t.Fatalf("expected replaced closable writer to be closed once, got %d", oldWriter.closeCount.Load())
	}
	if newWriter.closeCount.Load() != 0 {
		t.Fatalf("expected replacement writer to remain open, got %d closes", newWriter.closeCount.Load())
	}
}

func TestSessionStreamSerializesDirectAndHubWrites(t *testing.T) {
	hub := newStreamHub()
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443}
	writer := &concurrentDetectWriter{concurrencyCh: make(chan struct{}, 1)}
	stream := &sessionStream{
		remoteAddr: remoteAddr.String(),
		rawWriter:  writer,
	}
	hub.registerSession(remoteAddr, "", 123, stream)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := stream.writeFramed([]byte("response-payload")); err != nil {
			t.Errorf("direct write failed: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := hub.writeToIP(123, []byte("push-payload")); err != nil {
			t.Errorf("hub write failed: %v", err)
		}
	}()
	wg.Wait()

	select {
	case <-writer.concurrencyCh:
		t.Fatal("detected concurrent writes to the same session writer")
	default:
	}
	if writer.maxActive.Load() != 1 {
		t.Fatalf("expected maxActive=1, got %d", writer.maxActive.Load())
	}
}

func TestSessionStreamWriteUsesFramedSerialization(t *testing.T) {
	writer := &concurrentDetectWriter{}
	stream := &sessionStream{rawWriter: writer}

	n, err := stream.Write([]byte("payload"))
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if n != len("payload") {
		t.Fatalf("expected payload byte count, got %d", n)
	}
	if writer.maxActive.Load() != 1 {
		t.Fatalf("expected framed write to stay serialized, got %d", writer.maxActive.Load())
	}
}

func TestStreamHubUnregisterSessionKeepsReplacementOnSameRemoteAddr(t *testing.T) {
	hub := newStreamHub()
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443}
	oldWriter := &trackingWriteCloser{}
	newWriter := &trackingWriteCloser{}
	oldStream := &sessionStream{remoteAddr: remoteAddr.String(), rawWriter: oldWriter, rawCloser: oldWriter}
	newStream := &sessionStream{remoteAddr: remoteAddr.String(), rawWriter: newWriter, rawCloser: newWriter}

	hub.registerSession(remoteAddr, "", 123, oldStream)
	hub.registerSession(remoteAddr, "", 123, newStream)

	if err := hub.writeToIP(123, []byte("payload")); err != nil {
		t.Fatalf("expected replacement stream to stay registered, got %v", err)
	}
	if oldWriter.Len() != 0 {
		t.Fatalf("expected old stream to stay unused, wrote %d bytes", oldWriter.Len())
	}
	if newWriter.Len() == 0 {
		t.Fatal("expected replacement stream to receive framed payload")
	}
	if oldWriter.closeCount.Load() != 1 {
		t.Fatalf("expected replaced stream to be closed once, got %d", oldWriter.closeCount.Load())
	}
	if newWriter.closeCount.Load() != 0 {
		t.Fatalf("expected replacement stream to stay open, got %d closes", newWriter.closeCount.Load())
	}
}

func TestStreamHubUnregisterSessionKeepsReplacementAcrossRemoteAddrChange(t *testing.T) {
	hub := newStreamHub()
	oldRemoteAddr := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443}
	newRemoteAddr := &net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: 443}
	oldWriter := &trackingWriteCloser{}
	newWriter := &trackingWriteCloser{}
	oldStream := &sessionStream{remoteAddr: oldRemoteAddr.String(), rawWriter: oldWriter, rawCloser: oldWriter}
	newStream := &sessionStream{remoteAddr: newRemoteAddr.String(), rawWriter: newWriter, rawCloser: newWriter}

	hub.registerSession(oldRemoteAddr, "", 123, oldStream)
	hub.registerSession(newRemoteAddr, "", 123, newStream)

	if err := hub.writeToIP(123, []byte("payload")); err != nil {
		t.Fatalf("expected replacement stream to stay registered after addr change, got %v", err)
	}
	if oldWriter.Len() != 0 {
		t.Fatalf("expected old stream to stay unused, wrote %d bytes", oldWriter.Len())
	}
	if newWriter.Len() == 0 {
		t.Fatal("expected replacement stream to receive framed payload")
	}
	if oldWriter.closeCount.Load() != 1 {
		t.Fatalf("expected replaced stream to be closed once, got %d", oldWriter.closeCount.Load())
	}
	if newWriter.closeCount.Load() != 0 {
		t.Fatalf("expected replacement stream to stay open, got %d closes", newWriter.closeCount.Load())
	}
}

func TestStreamHubRoutesSameIPByNetworkKey(t *testing.T) {
	hub := newStreamHub()
	remoteA := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443}
	remoteB := &net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: 443}
	writerA := &trackingWriteCloser{}
	writerB := &trackingWriteCloser{}

	hub.registerSession(remoteA, "personal:sdl-alpha@user.ms.net", 123, &sessionStream{
		remoteAddr: remoteA.String(),
		rawWriter:  writerA,
		rawCloser:  writerA,
	})
	hub.registerSession(remoteB, "personal:sdl-beta@user.ms.net", 123, &sessionStream{
		remoteAddr: remoteB.String(),
		rawWriter:  writerB,
		rawCloser:  writerB,
	})

	if err := hub.writeToRoute("personal:sdl-beta@user.ms.net", 123, []byte("payload")); err != nil {
		t.Fatalf("writeToRoute failed: %v", err)
	}
	if writerA.Len() != 0 {
		t.Fatalf("expected alpha writer to stay untouched, wrote %d bytes", writerA.Len())
	}
	if writerB.Len() == 0 {
		t.Fatal("expected beta writer to receive framed payload")
	}
}

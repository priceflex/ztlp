package ztlp

import (
	"testing"
)

func TestReplayWindowSequential(t *testing.T) {
	w := NewReplayWindow(DefaultReplayWindow)
	for i := uint64(0); i < 100; i++ {
		if !w.CheckAndRecord(i) {
			t.Errorf("seq %d should be accepted", i)
		}
	}
}

func TestReplayWindowDuplicate(t *testing.T) {
	w := NewReplayWindow(DefaultReplayWindow)
	if !w.CheckAndRecord(1) {
		t.Error("seq 1 should be accepted")
	}
	if !w.CheckAndRecord(2) {
		t.Error("seq 2 should be accepted")
	}
	if w.CheckAndRecord(1) {
		t.Error("duplicate seq 1 should be rejected")
	}
	if w.CheckAndRecord(2) {
		t.Error("duplicate seq 2 should be rejected")
	}
}

func TestReplayWindowOutOfOrder(t *testing.T) {
	w := NewReplayWindow(DefaultReplayWindow)
	if !w.CheckAndRecord(5) {
		t.Error("seq 5 should be accepted")
	}
	if !w.CheckAndRecord(3) {
		t.Error("seq 3 should be accepted (within window, not seen)")
	}
	if !w.CheckAndRecord(4) {
		t.Error("seq 4 should be accepted (within window, not seen)")
	}
	if w.CheckAndRecord(3) {
		t.Error("duplicate seq 3 should be rejected")
	}
}

func TestReplayWindowTooOld(t *testing.T) {
	w := NewReplayWindow(DefaultReplayWindow)
	if !w.CheckAndRecord(100) {
		t.Error("seq 100 should be accepted")
	}
	// Seq 0 is now 100 behind, > window of 64
	if w.CheckAndRecord(0) {
		t.Error("too-old packet should be rejected")
	}
	// Seq 50 is 50 behind, within window
	if !w.CheckAndRecord(50) {
		t.Error("seq 50 should be accepted (within window)")
	}
}

func TestReplayWindowLargeGap(t *testing.T) {
	w := NewReplayWindow(DefaultReplayWindow)
	if !w.CheckAndRecord(0) {
		t.Error("seq 0 should be accepted")
	}
	// Jump far ahead — bitmap should be cleared
	if !w.CheckAndRecord(1000) {
		t.Error("seq 1000 should be accepted")
	}
	// Old packets should be rejected
	if w.CheckAndRecord(0) {
		t.Error("seq 0 should be rejected after large gap")
	}
	// Packet just before 1000 should work
	if !w.CheckAndRecord(999) {
		t.Error("seq 999 should be accepted")
	}
}

func TestReplayWindowZeroFirst(t *testing.T) {
	w := NewReplayWindow(DefaultReplayWindow)
	if !w.CheckAndRecord(0) {
		t.Error("first seq 0 should be accepted")
	}
	if w.CheckAndRecord(0) {
		t.Error("duplicate seq 0 should be rejected")
	}
}

func TestSessionStateNextSendSeq(t *testing.T) {
	s := NewSessionState(
		SessionID{},
		NodeID{},
		[32]byte{},
		[32]byte{},
		false,
	)
	for i := uint64(0); i < 10; i++ {
		seq := s.NextSendSeq()
		if seq != i {
			t.Errorf("NextSendSeq: got %d, want %d", seq, i)
		}
	}
}

func TestSessionStateCheckReplay(t *testing.T) {
	s := NewSessionState(
		SessionID{},
		NodeID{},
		[32]byte{},
		[32]byte{},
		false,
	)
	if !s.CheckReplay(1) {
		t.Error("seq 1 should be accepted")
	}
	if s.CheckReplay(1) {
		t.Error("duplicate seq 1 should be rejected")
	}
}

func TestSessionStateMultipath(t *testing.T) {
	s := NewSessionState(
		SessionID{},
		NodeID{},
		[32]byte{},
		[32]byte{},
		true,
	)
	if !s.Multipath {
		t.Error("multipath should be true")
	}
	// Multipath window is larger, so wider gaps should be accepted
	if !s.CheckReplay(500) {
		t.Error("seq 500 should be accepted")
	}
	// Window is 1024, so seq 0 (500 behind) should be within
	if !s.CheckReplay(0) {
		t.Error("seq 0 should be accepted (within multipath window)")
	}
}

func TestReplayWindowConcurrent(t *testing.T) {
	w := NewReplayWindow(DefaultReplayWindow)
	done := make(chan bool)

	// Multiple goroutines trying to record the same sequences
	for g := 0; g < 4; g++ {
		go func() {
			for i := uint64(0); i < 100; i++ {
				w.CheckAndRecord(i)
			}
			done <- true
		}()
	}

	for g := 0; g < 4; g++ {
		<-done
	}

	// After concurrent access, duplicates should still be rejected
	if w.CheckAndRecord(50) {
		t.Error("seq 50 should be rejected after concurrent recording")
	}
}

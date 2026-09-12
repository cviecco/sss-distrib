package sssdoc

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

const replayByteSize = 16
const defaultRPDuration = time.Second * 5
const defautMaxRPAge = time.Second * 45

type rpQueueEntry struct {
	creationTime time.Time
	pseudononce  []byte
}

type replayProtector struct {
	datamutex        sync.Mutex
	lastCreatedAt    time.Time
	replayNonceQueue []rpQueueEntry
	keyReader        io.Reader
	rpDuration       time.Duration
	maxAge           time.Duration
}

func NewReplayProtector() (*replayProtector, error) {
	hash := sha256.New
	secret := make([]byte, hash().Size())
	_, err := rand.Read(secret)
	if err != nil {
		return nil, err
	}
	hkreader := hkdf.New(hash, secret[:], nil, nil)

	rp := replayProtector{
		keyReader:  hkreader,
		rpDuration: defaultRPDuration,
		maxAge:     defautMaxRPAge,
	}

	return &rp, nil
}

func (rp *replayProtector) withLockAddNewNonce() ([]byte, error) {
	newSecret := make([]byte, replayByteSize)
	_, err := io.ReadFull(rp.keyReader, newSecret)
	if err != nil {
		return nil, err
	}
	newEntry := rpQueueEntry{
		creationTime: time.Now(),
		pseudononce:  newSecret[:],
	}

	rp.replayNonceQueue = append(rp.replayNonceQueue, newEntry)
	rp.lastCreatedAt = time.Now()
	return newSecret[:], nil
}

func (rp *replayProtector) withLockPurgeOldRpEntries() {
	numOld := 0
	for _, rpEntry := range rp.replayNonceQueue {
		if rpEntry.creationTime.Add(rp.maxAge).Before(time.Now()) {
			numOld += 1
		}
	}
	if numOld > 0 {
		rp.replayNonceQueue = rp.replayNonceQueue[numOld:]
	}

}

func (rp *replayProtector) GetProtectorBytes() ([]byte, error) {
	rp.datamutex.Lock()
	defer rp.datamutex.Unlock()
	// if the last one is very recent just return that one
	if rp.lastCreatedAt.Add(rp.rpDuration).After(time.Now()) {
		return rp.replayNonceQueue[len(rp.replayNonceQueue)-1].pseudononce, nil
	}
	rp.withLockPurgeOldRpEntries()
	_, err := rp.withLockAddNewNonce()
	if err != nil {
		return nil, err
	}
	return rp.replayNonceQueue[len(rp.replayNonceQueue)-1].pseudononce, nil
}

func (rp *replayProtector) CheckReplayExists(in []byte) bool {
	rp.datamutex.Lock()
	defer rp.datamutex.Unlock()
	rp.withLockPurgeOldRpEntries()
	for _, entry := range rp.replayNonceQueue {
		// A replay value is not private thus
		// we allow this simple comparison
		if bytes.Equal(in, entry.pseudononce) {
			return true
		}
	}
	return false
}

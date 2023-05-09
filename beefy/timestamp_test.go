package beefy_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestConvertTimestamp(t *testing.T) {
	var timestamp uint64 = 1678780392001
	t.Logf("timestamp uint64: %d ", timestamp)
	var timestampStr = "2023-03-14 15:53:12.001 +0800 CST"
	t.Logf("timestampStr: %s", timestampStr)

	timeTemplate1 := "2006-01-02 15:04:05 +0800 CST"
	t.Logf("timeTemplate1: %s", timeTemplate1)
	timestampFromstr1, err := time.ParseInLocation(timeTemplate1, timestampStr, time.Local)
	require.NoError(t, err)
	t.Logf("timestampFromstr1: %d", timestampFromstr1.UnixMilli())
	require.Equal(t, timestamp, uint64(timestampFromstr1.UnixMilli()))

	timeTemplate2 := "2006-01-02 15:04:05"
	t.Logf("timeTemplate2: %s", timeTemplate2)
	timestampFromstr2, err := time.ParseInLocation(timeTemplate2, timestampStr, time.Local)
	require.Error(t, err)
	t.Logf("timestampFromstr2: %d", timestampFromstr2.UnixMilli())

	timestampFromstr3, err := time.Parse(timeTemplate1, timestampStr)
	require.NoError(t, err)
	t.Logf("timestampFromstr3: %d", timestampFromstr3.UnixMilli())
	require.NotEqual(t, timestamp, uint64(timestampFromstr3.UnixMilli()))
	require.NotEqual(t, uint64(timestampFromstr1.UnixMilli()), uint64(timestampFromstr3.UnixMilli()))

	timestampFromstr4, err := time.Parse(timeTemplate1, timestampStr)
	require.NoError(t, err)
	t.Logf("timestampFromstr4: %d", timestampFromstr4.UnixMilli())
	require.NotEqual(t, timestamp, uint64(timestampFromstr4.UnixMilli()))
	require.Equal(t, uint64(timestampFromstr3.UnixMilli()), uint64(timestampFromstr4.UnixMilli()))

	// duration, err := time.ParseDuration(timestampStr)
	// require.NoError(t, err)
	// t.Logf("duration: %s", duration)
}

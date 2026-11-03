package common

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/Sangmoo/intrasec/internal/checks/checkstest"
)

func TestExposureDetected(t *testing.T) {
	tgt, s := checkstest.Serve(t, checkstest.Files{Paths: map[string]checkstest.File{
		"/.git/HEAD":       {ContentType: "text/plain", Body: "ref: refs/heads/main\n"},
		"/.env":            {ContentType: "text/plain", Body: "APP_ENV=production\nDB_PASSWORD=REDACTED_VALUE\nAPP_KEY=base64:REDACTED\n"},
		"/backup.sql":      {ContentType: "application/octet-stream", Body: "-- MySQL dump 10.13\nCREATE TABLE users (id int);\n"},
		"/config.php.bak":  {ContentType: "application/octet-stream", Body: "<?php $db_pass = 'x';"},
		"/uploads/":        {ContentType: "text/html", Body: "<html><head><title>Index of /uploads</title></head></html>"},
		"/WEB-INF/web.xml": {ContentType: "application/xml", Body: `<?xml version="1.0"?><web-app></web-app>`},
	}})
	fs, err := exposureCheck{}.Run(context.Background(), tgt, s)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range fs {
		got = append(got, f.CheckID+" "+f.Target[strings.LastIndex(f.Target, "/"):])
		if strings.Contains(f.Evidence.Note+f.Evidence.Response, "REDACTED_VALUE") {
			t.Errorf("비밀값이 근거에 포함됨: %+v", f.Evidence)
		}
	}
	sort.Strings(got)
	want := []string{
		"COMMON-EXP-001 /HEAD",
		"COMMON-EXP-002 /.env",
		"COMMON-EXP-002 /backup.sql",
		"COMMON-EXP-002 /config.php.bak",
		"COMMON-EXP-002 /web.xml",
		"COMMON-EXP-003 /",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("want %v\n got %v", want, got)
	}
}

func TestExposureSoftNotFound(t *testing.T) {
	tgt, s := checkstest.Serve(t, checkstest.Files{SoftNotFound: true})
	fs, err := exposureCheck{}.Run(context.Background(), tgt, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Fatalf("soft 404 서버에서 오탐: %+v", fs)
	}
}

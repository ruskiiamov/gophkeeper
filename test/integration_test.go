package test

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	goPath      = "/usr/local/go/bin/go"
	dockerPath  = "/usr/bin/docker"
	serverPath  = "/server"
	client1Path = "/client1"
	client2Path = "/client2"
)

func TestGophkeeper(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := exec.CommandContext(ctx, dockerPath, "run", "--rm",
		"-p", "54320:5432",
		"--name", "gophkeeper-postgres",
		"-e", "POSTGRES_PASSWORD=root",
		"-e", "POSTGRES_USER=root",
		"-e", "POSTGRES_DB=gophkeeper",
		"-d", "postgres",
	).Run()
	if err != nil {
		t.Fatal(err)
	}
	defer exec.Command(dockerPath, "stop", "gophkeeper-postgres").Run()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(wd+client1Path); os.IsNotExist(err) {
		err := exec.CommandContext(ctx, goPath, "build", "-o", wd+client1Path+"/main", "../cmd/client/main.go").Run()
		if err != nil {
			t.Fatal(err)
		}
	}
	defer os.RemoveAll(wd+client1Path)

	if _, err := os.Stat(wd+client2Path); os.IsNotExist(err) {
		err := exec.CommandContext(ctx, goPath, "build", "-o", wd+client2Path+"/main", "../cmd/client/main.go").Run()
		if err != nil {
			t.Fatal(err)
		}
	}
	defer os.RemoveAll(wd+client2Path)

	if _, err := os.Stat(wd+serverPath); os.IsNotExist(err) {
		err := exec.CommandContext(ctx, goPath, "build", "-o", wd+serverPath+"/main", "../cmd/server/main.go").Run()
		if err != nil {
			t.Fatal(err)
		}
	}
	defer os.RemoveAll(wd+serverPath)

	serverCmd := exec.Command(wd+serverPath+"/main")
	if err := serverCmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func () {
		t.Log("start waiting stop server...")
		serverCmd.Process.Signal(syscall.SIGINT)
		serverCmd.Wait()
		t.Log("server stopped")
	}()
	defer os.RemoveAll(wd+"/server_data")

	time.Sleep(2*time.Second)

	os.Chdir(wd+client1Path)
	defer os.Chdir(wd)
	out, err := exec.CommandContext(ctx, "./main", "reg", "testuser", "qwertyui").CombinedOutput()
	if err != nil || len(out) != 0 {
		t.Fatal(string(out))
	}
	t.Log("registration OK")

	time.Sleep(2*time.Second)

	out, err = exec.CommandContext(ctx, "./main", "auth", "testuser", "qwertyui").CombinedOutput()
	if err != nil || len(out) != 0 {
		t.Fatal(string(out))
	}
	t.Log("authentication client 1 OK")

	testMessage := "My test message"

	out, err = exec.CommandContext(ctx, "./main", "add", "text", testMessage).CombinedOutput()
	if err != nil || len(out) != 0 {
		t.Fatal(string(out))
	}
	t.Log("text add client 1 OK")

	out, err = exec.CommandContext(ctx, "./main", "list").CombinedOutput()
	if err != nil || len(out) == 0 {
		t.Fatal("empty list")
	}
	t.Log("get list client 1 OK")

	id := strings.Split(string(out), " ")[0]

	out, err = exec.CommandContext(ctx, "./main", "get", id).CombinedOutput()
	if err != nil || len(out) == 0 {
		t.Fatal("empty list")
	}
	receivedMessage := strings.TrimSuffix(string(out), "\n")

	if testMessage != receivedMessage {
		t.Fatalf("want=%s\nreceived=%s\n", testMessage, receivedMessage)
	}
	t.Log("get text client 1 OK")

	out, err = exec.CommandContext(ctx, "./main", "sync").CombinedOutput()
	if err != nil || len(out) != 0 {
		t.Fatal(string(out))
	}
	t.Log("sync client 1 OK")

	os.Chdir(wd+client2Path)
	defer os.Chdir(wd)
	out, err = exec.CommandContext(ctx, "./main", "auth", "testuser", "qwertyui").CombinedOutput()
	if err != nil || len(out) != 0 {
		t.Fatal(string(out))
	}
	t.Log("authentication client 2 OK")

	out, err = exec.CommandContext(ctx, "./main", "sync").CombinedOutput()
	if err != nil || len(out) != 0 {
		t.Fatal(string(out))
	}
	t.Log("sync client 2 OK")

	out, err = exec.CommandContext(ctx, "./main", "get", id).CombinedOutput()
	if err != nil || len(out) == 0 {
		t.Fatal("empty list")
	}
	receivedMessage = strings.TrimSuffix(string(out), "\n")

	if testMessage != receivedMessage {
		t.Fatalf("want=%s\nreceived=%s\n", testMessage, receivedMessage)
	}
	t.Log("get text client 2 OK")

	out, err = exec.CommandContext(ctx, "./main", "updpass", "qwertyui", "12345678").CombinedOutput()
	if err != nil || len(out) != 0 {
		t.Fatal(string(out))
	}
	t.Log("update password client 2 OK")

	out, err = exec.CommandContext(ctx, "./main", "auth", "testuser", "12345678").CombinedOutput()
	if err != nil || len(out) != 0 {
		t.Fatal(string(out))
	}
	t.Log("authentication after update client 2 OK")

	out, err = exec.CommandContext(ctx, "./main", "get", id).CombinedOutput()
	if err != nil || len(out) == 0 {
		t.Fatal("empty list")
	}
	receivedMessage = strings.TrimSuffix(string(out), "\n")

	if testMessage != receivedMessage {
		t.Fatalf("want=%s\nreceived=%s\n", testMessage, receivedMessage)
	}
	t.Log("get text after pass update client 2 OK")

	os.Chdir(wd+client1Path)
	defer os.Chdir(wd)
	out, err = exec.CommandContext(ctx, "./main", "auth", "testuser", "12345678").CombinedOutput()
	if err != nil || len(out) != 0 {
		t.Fatal(string(out))
	}
	t.Log("authentication after pass update client 1 OK")

	out, err = exec.CommandContext(ctx, "./main", "get", id).CombinedOutput()
	if err != nil || len(out) == 0 {
		t.Fatal("empty list")
	}
	receivedMessage = strings.TrimSuffix(string(out), "\n")

	if testMessage != receivedMessage {
		t.Fatalf("want=%s\nreceived=%s\n", testMessage, receivedMessage)
	}
	t.Log("get text after pass update client 1 OK")

	t.Log("all assertions done") 
}

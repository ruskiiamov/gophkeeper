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
	serverPath  = "./server"
	client1Path = "./client1"
	client2Path = "./client2"
)

func TestGophkeeper(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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

	if _, err := os.Stat(client1Path); os.IsNotExist(err) {
		err := exec.CommandContext(ctx, goPath, "build", "-o", client1Path+"/main", "../cmd/client/main.go").Run()
		if err != nil {
			t.Fatal(err)
		}
	}
	defer os.RemoveAll(client1Path)

	if _, err := os.Stat(client2Path); os.IsNotExist(err) {
		err := exec.CommandContext(ctx, goPath, "build", "-o", client2Path+"/main", "../cmd/client/main.go").Run()
		if err != nil {
			t.Fatal(err)
		}
	}
	defer os.RemoveAll(client2Path)

	if _, err := os.Stat(serverPath); os.IsNotExist(err) {
		err := exec.CommandContext(ctx, goPath, "build", "-o", serverPath+"/main", "../cmd/server/main.go").Run()
		if err != nil {
			t.Fatal(err)
		}
	}
	defer os.RemoveAll(serverPath)

	serverCmd := exec.Command(serverPath+"/main")
	if err := serverCmd.Start(); err != nil {
		t.Fatal(err)
	}

	go func() {
		<-ctx.Done()
		serverCmd.Process.Signal(syscall.SIGTERM)
	}()

	os.Chdir(client1Path)
	defer os.Chdir("..")
	out, err := exec.CommandContext(ctx, "./main", "reg", "testuser", "qwertyui").CombinedOutput()
	if err != nil || len(out) != 0 {
		t.Fatal(string(out))
	}

	out, err = exec.CommandContext(ctx, "./main", "auth", "testuser", "qwertyui").CombinedOutput()
	if err != nil || len(out) != 0 {
		t.Fatal(string(out))
	}

	testMessage := "My test message"

	out, err = exec.CommandContext(ctx, "./main", "add", "text", testMessage).CombinedOutput()
	if err != nil || len(out) != 0 {
		t.Fatal(string(out))
	}

	out, err = exec.CommandContext(ctx, "./main", "list").CombinedOutput()
	if err != nil || len(out) == 0 {
		t.Fatal("empty list")
	}

	id := strings.Split(string(out), " ")[0]

	out, err = exec.CommandContext(ctx, "./main", "get", id).CombinedOutput()
	if err != nil || len(out) == 0 {
		t.Fatal("empty list")
	}
	receivedMessage := strings.TrimSuffix(string(out), "\n")

	if testMessage != receivedMessage {
		t.Fatalf("want=%s\nreceived=%s\n", testMessage, receivedMessage)
	}

	out, err = exec.CommandContext(ctx, "./main", "sync").CombinedOutput()
	if err != nil || len(out) != 0 {
		t.Fatal(string(out))
	}

	cancel()
	serverCmd.Wait()
}

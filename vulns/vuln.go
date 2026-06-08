// Package vulns is an INTENTIONALLY VULNERABLE test lab (DVWA/WebGoat style)
// used to validate a SAST taint-tracking scanner. DO NOT deploy. NO mitigations.
package vulns

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"text/template"

	_ "github.com/go-sql-driver/mysql"
)

// Hardcoded FAKE secrets with realistic shapes.
// CWE-798: Use of Hard-coded Credentials
const awsSecretKey = "AKIAIOSFODNN7EXAMPLE/wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
const apiToken = "ghp_aB3dEfGh1jKlMn0pQrStUvWxYz0123456789"

// CWE-78: OS Command Injection
func cmdInjectHandler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd") // untrusted HTTP param
	out, _ := exec.Command("sh", "-c", cmd).CombinedOutput()
	w.Write(out)
}

// CWE-89: SQL Injection
func sqlInjectHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id") // untrusted HTTP param
	db, _ := sql.Open("mysql", "root:root@/app")
	query := fmt.Sprintf("SELECT name, email FROM users WHERE id = %s", id)
	rows, _ := db.Query(query)
	defer rows.Close()
	for rows.Next() {
		var name, email string
		rows.Scan(&name, &email)
		fmt.Fprintf(w, "%s:%s\n", name, email)
	}
}

// CWE-918: Server-Side Request Forgery (SSRF)
func ssrfHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url") // untrusted HTTP param
	resp, err := http.Get(target)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	fmt.Fprintf(w, "fetched %s status %d", target, resp.StatusCode)
}

// CWE-22: Path Traversal
func pathTraversalHandler(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query().Get("path") // untrusted HTTP param
	data, err := os.ReadFile(p)
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	w.Write(data)
}

// CWE-89: SQL Injection via request header
func headerSQLHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Header.Get("X-User") // untrusted HTTP header
	db, _ := sql.Open("mysql", "root:root@/app")
	q := "SELECT role FROM accounts WHERE username = '" + user + "'"
	rows, _ := db.Query(q)
	defer rows.Close()
	fmt.Fprintln(w, "queried")
}

// CWE-78: OS Command Injection via POST body
func uploadExecHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	name := r.FormValue("filename") // untrusted POST body field
	out, _ := exec.Command("bash", "-c", "tar xzf "+name).CombinedOutput()
	w.Write(out)
}

// CWE-94: Code Injection via Server-Side Template Injection
func templateInjectHandler(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("tpl") // untrusted HTTP param
	t, err := template.New("page").Parse(raw)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	t.Execute(w, nil)
}

// CWE-327: Use of a Broken Cryptographic Algorithm (MD5)
func weakHashHandler(w http.ResponseWriter, r *http.Request) {
	pw := r.URL.Query().Get("pw") // untrusted HTTP param
	sum := md5.Sum([]byte(pw))
	fmt.Fprintf(w, "%x", sum)
}

// CWE-295: Improper Certificate Validation (TLS verification disabled)
func insecureTLSFetch(host string) (*http.Response, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	return client.Get("https://" + host)
}

// CWE-330: Use of Insufficiently Random Values (predictable token)
func makeSessionToken() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 32)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))] // math/rand is not cryptographically secure
	}
	return string(b)
}

// CWE-601: Open Redirect
func redirectHandler(w http.ResponseWriter, r *http.Request) {
	dest := r.URL.Query().Get("next") // untrusted HTTP param
	http.Redirect(w, r, dest, http.StatusFound)
}

// CWE-79: Reflected Cross-Site Scripting
func xssHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q") // untrusted HTTP param
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<div>Results for: %s</div>", q)
}

// CWE-78: OS Command Injection via environment variable and CLI args
func envCmdRunner() {
	region := os.Getenv("DEPLOY_REGION") // untrusted env input
	args := os.Args                       // untrusted CLI args
	target := "default"
	if len(args) > 1 {
		target = args[1]
	}
	exec.Command("sh", "-c", "deploy --region "+region+" --target "+target).Run()
}

// RegisterRoutes wires up every vulnerable handler.
func RegisterRoutes() {
	http.HandleFunc("/cmd", cmdInjectHandler)
	http.HandleFunc("/user", sqlInjectHandler)
	http.HandleFunc("/fetch", ssrfHandler)
	http.HandleFunc("/read", pathTraversalHandler)
	http.HandleFunc("/role", headerSQLHandler)
	http.HandleFunc("/upload", uploadExecHandler)
	http.HandleFunc("/render", templateInjectHandler)
	http.HandleFunc("/hash", weakHashHandler)
	http.HandleFunc("/go", redirectHandler)
	http.HandleFunc("/search", xssHandler)
	_ = awsSecretKey
	_ = apiToken
	_, _ = insecureTLSFetch("example.com")
	_ = makeSessionToken()
}
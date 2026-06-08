package vulns;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.sql.*;
import java.util.*;
import javax.naming.*;
import javax.servlet.*;
import javax.servlet.http.*;
import javax.xml.stream.*;
import javax.xml.parsers.*;
import org.xml.sax.InputSource;

// Intentionally vulnerable SAST test lab. DO NOT deploy. No mitigations on purpose.
public class Vuln extends HttpServlet {

    // CWE-798: Use of hard-coded credentials
    private static final String DB_PASSWORD = "Sup3rS3cr3t!Pa55w0rd2026";
    // CWE-798: hard-coded AWS-shaped secret access key
    private static final String AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    private static final String JDBC_URL = "jdbc:mysql://10.0.0.5:3306/prod";

    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            String which = request.getParameter("which");
            if ("cmd".equals(which)) cmdInjection(request);
            else if ("sql".equals(which)) sqlInjection(request);
            else if ("ssrf".equals(which)) ssrf(request);
            else if ("xxe".equals(which)) xxe(request);
            else if ("path".equals(which)) pathTraversal(request, response);
            else if ("clazz".equals(which)) unsafeClassLoad(request);
            else if ("ldap".equals(which)) ldapInjection(request);
            else if ("redir".equals(which)) openRedirect(request, response);
            else if ("xpath".equals(which)) xpathInjection(request);
            else if ("log".equals(which)) logInjection(request);
            else weakHash(request);
        } catch (Exception e) {
            response.getWriter().println(e.getMessage());
        }
    }

    public void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        try { deserialize(req); } catch (Exception e) { throw new IOException(e); }
    }

    // CWE-78: OS Command Injection
    void cmdInjection(HttpServletRequest request) throws IOException {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec(cmd);
    }

    // CWE-89: SQL Injection
    void sqlInjection(HttpServletRequest request) throws SQLException {
        String id = request.getParameter("id");
        Connection con = DriverManager.getConnection(JDBC_URL, "root", DB_PASSWORD);
        Statement st = con.createStatement();
        ResultSet rs = st.executeQuery("SELECT * FROM users WHERE id = " + id);
        rs.close();
    }

    // CWE-502: Deserialization of Untrusted Data
    void deserialize(HttpServletRequest req) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(req.getInputStream());
        Object o = ois.readObject();
        System.out.println(o);
    }

    // CWE-611: XML External Entity (XXE) via StAX without disabling DTD
    void xxe(HttpServletRequest request) throws Exception {
        String xml = request.getParameter("xml");
        XMLInputFactory factory = XMLInputFactory.newInstance();
        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xml));
        while (reader.hasNext()) reader.next();
    }

    // CWE-611: XXE via DocumentBuilder without disabling DTD
    void xxeDom(HttpServletRequest request) throws Exception {
        String xml = request.getParameter("doc");
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse(new InputSource(new StringReader(xml)));
    }

    // CWE-327: Use of a Broken or Risky Cryptographic Algorithm (MD5)
    void weakHash(HttpServletRequest request) throws Exception {
        String data = request.getParameter("data");
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(data.getBytes());
        System.out.println(Arrays.toString(digest));
    }

    // CWE-918: Server-Side Request Forgery (SSRF)
    void ssrf(HttpServletRequest request) throws IOException {
        String url = request.getParameter("url");
        URLConnection conn = new URL(url).openConnection();
        InputStream in = conn.getInputStream();
        in.read();
    }

    // CWE-470: Unsafe Reflection / Class ForName from untrusted input
    void unsafeClassLoad(HttpServletRequest request) throws Exception {
        String c = request.getParameter("c");
        Class<?> clazz = Class.forName(c);
        clazz.getDeclaredConstructor().newInstance();
    }

    // CWE-22: Path Traversal
    void pathTraversal(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String file = request.getParameter("file");
        byte[] bytes = Files.readAllBytes(Paths.get("/var/data/" + file));
        response.getOutputStream().write(bytes);
    }

    // CWE-90: LDAP Injection
    void ldapInjection(HttpServletRequest request) throws NamingException {
        String user = request.getParameter("user");
        DirContext ctx = new InitialDirContext();
        ctx.search("ou=people,dc=corp,dc=com", "(uid=" + user + ")", new SearchControls());
    }

    // CWE-601: Open Redirect
    void openRedirect(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String target = request.getParameter("next");
        response.sendRedirect(target);
    }

    // CWE-643: XPath Injection
    void xpathInjection(HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        javax.xml.xpath.XPath xp = javax.xml.xpath.XPathFactory.newInstance().newXPath();
        xp.compile("/users/user[@name='" + name + "']");
    }

    // CWE-117: Improper Output Neutralization for Logs (Log Injection)
    void logInjection(HttpServletRequest request) {
        String note = request.getParameter("note");
        System.out.println("USER_NOTE: " + note);
    }

    // CWE-78: OS Command Injection from CLI args / stdin / env
    public static void main(String[] args) throws IOException {
        String envCmd = System.getenv("USER_CMD");
        if (envCmd != null) Runtime.getRuntime().exec(envCmd);
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        String line = br.readLine();
        if (line != null) Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", line});
        if (args.length > 0) Runtime.getRuntime().exec(args[0]);
    }
}
---
title: Example Title
permalink: /alerts-advisories/alerts/2024/al-2024-040/
variant: tiptap
description: ""
---
<h1><strong>Security Bulletin 11 Apr 2024</strong></h1>
<p>Published on 11 Apr 2024</p>
<p></p>
<p>SingCERT's Security Bulletin summarises the list of vulnerabilities collated
from the National Institute of Standards and Technology (NIST)'s National
Vulnerability Database (NVD) in the past week.</p>
<p>The vulnerabilities are tabled based on severity, in accordance to their
CVSSv3 base scores:</p>
<p>
<br>
</p>
<table>
<tbody>
<tr>
<td rowspan="1" colspan="1">
<p>Critical</p>
</td>
<td rowspan="1" colspan="1">
<p>vulnerabilities with a base score of 9.0 to 10.0</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>High</p>
</td>
<td rowspan="1" colspan="1">
<p>vulnerabilities with a base score of 7.0 to 8.9</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>Medium</p>
</td>
<td rowspan="1" colspan="1">
<p>vulnerabilities with a base score of 4.0 to 6.9</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>Low</p>
</td>
<td rowspan="1" colspan="1">
<p>vulnerabilities with a base score of 0.1 to 3.9</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>None</p>
</td>
<td rowspan="1" colspan="1">
<p>vulnerabilities with a base score of 0.0</p>
</td>
</tr>
</tbody>
</table>
<p>
<br>
</p>
<p>For those vulnerabilities without assigned CVSS scores, please visit <strong><a href="https://nvd.nist.gov/" class="text-link" rel="noopener noreferrer nofollow" target="_blank">NVD</a></strong> for
the updated CVSS vulnerability entries.</p>
<p><strong><u>CRITICAL VULNERABILITIES</u></strong>
</p>
<table>
<tbody>
<tr>
<th rowspan="1" colspan="1">
<p><strong>CVE Number</strong>
</p>
</th>
<th rowspan="1" colspan="1">
<p><strong>Description</strong>
</p>
</th>
<th rowspan="1" colspan="1">
<p><strong>Base Score</strong>
</p>
</th>
<th rowspan="1" colspan="1">
<p><strong>Reference</strong>
</p>
</th>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-24576</p>
</td>
<td rowspan="1" colspan="1">
<p>Rust is a programming language. The Rust Security Response WG was notified
that the Rust standard library prior to version 1.77.2 did not properly
escape arguments when invoking batch files (with the <code>bat</code> and <code>cmd</code> extensions)
on Windows using the <code>Command</code>. An attacker able to control the
arguments passed to the spawned process could execute arbitrary shell commands
by bypassing the escaping. The severity of this vulnerability is critical
for those who invoke batch files on Windows with untrusted arguments. No
other platform or use is affected.
<br>
<br>The <code>Command::arg</code> and <code>Command::args</code> APIs state in
their documentation that the arguments will be passed to the spawned process
as-is, regardless of the content of the arguments, and will not be evaluated
by a shell. This means it should be safe to pass untrusted input as an
argument.
<br>
<br>On Windows, the implementation of this is more complex than other platforms,
because the Windows API only provides a single string containing all the
arguments to the spawned process, and it's up to the spawned process to
split them. Most programs use the standard C run-time argv, which in practice
results in a mostly consistent way arguments are splitted.
<br>
<br>One exception though is <code>cmd.exe</code> (used among other things to
execute batch files), which has its own argument splitting logic. That
forces the standard library to implement custom escaping for arguments
passed to batch files. Unfortunately it was reported that our escaping
logic was not thorough enough, and it was possible to pass malicious arguments
that would result in arbitrary shell execution.
<br>
<br>Due to the complexity of <code>cmd.exe</code>, we didn't identify a solution
that would correctly escape arguments in all cases. To maintain our API
guarantees, we improved the robustness of the escaping code, and changed
the <code>Command</code> API to return an [`InvalidInput`][4] error when
it cannot safely escape an argument. This error will be emitted when spawning
the process.
<br>
<br>The fix is included in Rust 1.77.2. Note that the new escaping logic for
batch files errs on the conservative side, and could reject valid arguments.
Those who implement the escaping themselves or only handle trusted inputs
on Windows can also use the <code>CommandExt::raw_arg</code> method to bypass
the standard library's escaping logic.</p>
</td>
<td rowspan="1" colspan="1">
<p>10</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-24576</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-22004</p>
</td>
<td rowspan="1" colspan="1">
<p>Due to length check, an attacker with privilege access on a Linux Nonsecure
operating system can trigger a vulnerability and leak the secure&nbsp;memory
from the Trusted Application</p>
</td>
<td rowspan="1" colspan="1">
<p>10</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-22004</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-48426</p>
</td>
<td rowspan="1" colspan="1">
<p>u-boot bug that allows for u-boot shell and interrupt over UART</p>
</td>
<td rowspan="1" colspan="1">
<p>10</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-48426</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-25096</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Control of Generation of Code ('Code Injection') vulnerability
in Canto Inc. Canto allows Code Injection.This issue affects Canto: from
n/a through 3.0.7.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>10</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-25096</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31286</p>
</td>
<td rowspan="1" colspan="1">
<p>Unrestricted Upload of File with Dangerous Type vulnerability in J.N.
Breetvelt a.K.A. OpaJaap WP Photo Album Plus.This issue affects WP Photo
Album Plus: from n/a before 8.6.03.005.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>9.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31286</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31280</p>
</td>
<td rowspan="1" colspan="1">
<p>Unrestricted Upload of File with Dangerous Type vulnerability in Andy
Moyle Church Admin.This issue affects Church Admin: from n/a through 4.1.5.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>9.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31280</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-25693</p>
</td>
<td rowspan="1" colspan="1">
<p>There is a path traversal in Esri Portal for ArcGIS versions &lt;= 11.2.
Successful exploitation may allow a remote, authenticated attacker to traverse
the file system to access files or execute code outside of the intended
directory.&nbsp;</p>
</td>
<td rowspan="1" colspan="1">
<p>9.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-25693</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-24707</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Control of Generation of Code ('Code Injection') vulnerability
in Cwicly Builder, SL. Cwicly allows Code Injection.This issue affects
Cwicly: from n/a through 1.4.0.2.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>9.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-24707</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31390</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Control of Generation of Code ('Code Injection') vulnerability
in Soflyy Breakdance allows Code Injection.This issue affects Breakdance:
from n/a through 1.7.0.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>9.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31390</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31380</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Control of Generation of Code ('Code Injection') vulnerability
in Soflyy Oxygen Builder allows Code Injection.This issue affects Oxygen
Builder: from n/a through 4.8.2.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>9.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31380</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27972</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Neutralization of Special Elements used in a Command ('Command
Injection') vulnerability in Very Good Plugins WP Fusion Lite allows Command
Injection.This issue affects WP Fusion Lite: from n/a through 3.41.24.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>9.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27972</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-25918</p>
</td>
<td rowspan="1" colspan="1">
<p>Unrestricted Upload of File with Dangerous Type vulnerability in InstaWP
Team InstaWP Connect allows Code Injection.This issue affects InstaWP Connect:
from n/a through 0.1.0.8.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>9.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-25918</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3136</p>
</td>
<td rowspan="1" colspan="1">
<p>The MasterStudy LMS plugin for WordPress is vulnerable to Local File Inclusion
in all versions up to, and including, 3.3.3 via the 'template' parameter.
This makes it possible for unauthenticated attackers to include and execute
arbitrary files on the server, allowing the execution of any PHP code in
those files. This can be used to bypass access controls, obtain sensitive
data, or achieve code execution in cases where images and other “safe”
file types can be uploaded and included.</p>
</td>
<td rowspan="1" colspan="1">
<p>9.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3136</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2804</p>
</td>
<td rowspan="1" colspan="1">
<p>The Network Summary plugin for WordPress is vulnerable to SQL Injection
via the 'category' parameter in all versions up to, and including, 2.0.11
due to insufficient escaping on the user supplied parameter and lack of
sufficient preparation on the existing SQL query. This makes it possible
for unauthenticated attackers to append additional SQL queries into already
existing queries that can be used to extract sensitive information from
the database.</p>
</td>
<td rowspan="1" colspan="1">
<p>9.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2804</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1813</p>
</td>
<td rowspan="1" colspan="1">
<p>The Simple Job Board plugin for WordPress is vulnerable to PHP Object
Injection in all versions up to, and including, 2.11.0 via deserialization
of untrusted input in the job_board_applicant_list_columns_value function.
This makes it possible for unauthenticated attackers to inject a PHP Object.
If a POP chain is present via an additional plugin or theme installed on
the target system, it could allow the attacker to delete arbitrary files,
retrieve sensitive data, or execute code when a submitted job application
is viewed.</p>
</td>
<td rowspan="1" colspan="1">
<p>9.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1813</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-1083</p>
</td>
<td rowspan="1" colspan="1">
<p>An unauthenticated remote attacker who is aware of a&nbsp;MQTT topic name
can send and receive messages, including GET/SET configuration commands,
reboot commands and firmware updates.</p>
</td>
<td rowspan="1" colspan="1">
<p>9.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-1083</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31224</p>
</td>
<td rowspan="1" colspan="1">
<p>GPT Academic provides interactive interfaces for large language models.
A vulnerability was found in gpt_academic versions 3.64 through 3.73. The
server deserializes untrustworthy data from the client, which may risk
remote code execution. Any device that exposes the GPT Academic service
to the Internet is vulnerable. Version 3.74 contains a patch for the issue.
There are no known workarounds aside from upgrading to a patched version.</p>
</td>
<td rowspan="1" colspan="1">
<p>9.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31224</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31849</p>
</td>
<td rowspan="1" colspan="1">
<p>A path traversal vulnerability exists in the Java version of CData Connect
&lt; 23.4.8846 when running using the embedded Jetty server, which could
allow an unauthenticated remote attacker to gain complete administrative
access to the application.</p>
</td>
<td rowspan="1" colspan="1">
<p>9.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31849</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31848</p>
</td>
<td rowspan="1" colspan="1">
<p>A path traversal vulnerability exists in the Java version of CData API
Server &lt; 23.4.8844 when running using the embedded Jetty server, which
could allow an unauthenticated remote attacker to gain complete administrative
access to the application.</p>
</td>
<td rowspan="1" colspan="1">
<p>9.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31848</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31218</p>
</td>
<td rowspan="1" colspan="1">
<p>Webhood is a self-hosted URL scanner used analyzing phishing and malicious
sites. Webhood's backend container images in versions 0.9.0 and earlier
are subject to Missing Authentication for Critical Function vulnerability.
This vulnerability allows an unauthenticated attacker to send a HTTP request
to the database (Pocketbase) admin API to create an admin account. The
Pocketbase admin API does not check for authentication/authorization when
creating an admin account when no admin accounts have been added. In its
default deployment, Webhood does not create a database admin account. Therefore,
unless users have manually created an admin account in the database, an
admin account will not exist in the deployment and the deployment is vulnerable.
Versions starting from 0.9.1 are patched. The patch creates a randomly
generated admin account if admin accounts have not already been created
i.e. the vulnerability is exploitable in the deployment. As a workaround,
users can disable access to URL path starting with <code>/api/admins</code> entirely.
With this workaround, the vulnerability is not exploitable via network.</p>
</td>
<td rowspan="1" colspan="1">
<p>9.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31218</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-21894</p>
</td>
<td rowspan="1" colspan="1">
<p>A heap overflow vulnerability in IPSec component of Ivanti Connect Secure
(9.x, 22.x) and Ivanti Policy Secure allows an unauthenticated malicious
user to send specially crafted requests in-order-to crash the service thereby
causing a DoS attack. In certain conditions this may lead to execution
of arbitrary code</p>
</td>
<td rowspan="1" colspan="1">
<p>9.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-21894</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-45590</p>
</td>
<td rowspan="1" colspan="1">
<p>An improper control of generation of code ('code injection') in Fortinet
FortiClientLinux version 7.2.0, 7.0.6 through 7.0.10 and 7.0.3 through
7.0.4 allows attacker to execute unauthorized code or commands via tricking
a FortiClientLinux user into visiting a malicious website</p>
</td>
<td rowspan="1" colspan="1">
<p>9.6</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-45590</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2692</p>
</td>
<td rowspan="1" colspan="1">
<p>SiYuan version 3.0.3 allows executing arbitrary commands on the server.
This is possible because the application is vulnerable to Server Side XSS.</p>
</td>
<td rowspan="1" colspan="1">
<p>9.6</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2692</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-6320</p>
</td>
<td rowspan="1" colspan="1">
<p>A command injection vulnerability exists in the com.webos.service.connectionmanager/tv/setVlanStaticAddress
endpoint on webOS versions 5 and 6. A series of specially crafted requests
can lead to command execution as the dbus user. An attacker can make authenticated
requests to trigger this vulnerability.
<br>
<br>Full versions and TV models affected:
<br>* webOS 5.5.0 - 04.50.51 running on OLED55CXPUA&nbsp;
<br>
<br>* webOS 6.3.3-442 (kisscurl-kinglake) - 03.36.50 running on OLED48C1PUB
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>9.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-6320</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-6319</p>
</td>
<td rowspan="1" colspan="1">
<p>A command injection vulnerability exists in the getAudioMetadata&nbsp;method
from the com.webos.service.attachedstoragemanager service on webOS version
4 through 7. A series of specially crafted requests can lead to command
execution as the root user. An attacker can make authenticated requests
to trigger this vulnerability.
<br>
<br>* webOS 4.9.7 - 5.30.40 running on LG43UM7000PLA&nbsp;
<br>
<br>* webOS 5.5.0 - 04.50.51 running on OLED55CXPUA&nbsp;
<br>
<br>* webOS 6.3.3-442 (kisscurl-kinglake) - 03.36.50 running on OLED48C1PUB&nbsp;
<br>
<br>* webOS 7.3.1-43 (mullet-mebin) - 03.33.85 running on OLED55A23LA
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>9.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-6319</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-6318</p>
</td>
<td rowspan="1" colspan="1">
<p>A command injection vulnerability exists in the processAnalyticsReport&nbsp;method
from the com.webos.service.cloudupload&nbsp;service on webOS version 5
through 7. A series of specially crafted requests can lead to command execution
as the root user. An attacker can make authenticated requests to trigger
this vulnerability.
<br>
<br>Full versions and TV models affected:
<br>
<br>* webOS 5.5.0 - 04.50.51 running on OLED55CXPUA&nbsp;
<br>
<br>* webOS 6.3.3-442 (kisscurl-kinglake) - 03.36.50 running on OLED48C1PUB&nbsp;
<br>
<br>* webOS 7.3.1-43 (mullet-mebin) - 03.33.85 running on OLED55A23LA
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>9.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-6318</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31345</p>
</td>
<td rowspan="1" colspan="1">
<p>Unrestricted Upload of File with Dangerous Type vulnerability in Sukhchain
Singh Auto Poster.This issue affects Auto Poster: from n/a through 1.2.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>9.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31345</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-36645</p>
</td>
<td rowspan="1" colspan="1">
<p>SQL injection vulnerability in ITB-GmbH TradePro v9.5, allows remote attackers
to run SQL queries via oordershow component in customer function.</p>
</td>
<td rowspan="1" colspan="1">
<p>9.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-36645</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27951</p>
</td>
<td rowspan="1" colspan="1">
<p>Unrestricted Upload of File with Dangerous Type vulnerability in Themeisle
Multiple Page Generator Plugin – MPG allows Upload a Web Shell to a Web
Server.This issue affects Multiple Page Generator Plugin – MPG: from n/a
through 3.4.0.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>9.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27951</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29990</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft Azure Kubernetes Service Confidential Container Elevation of
Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29990</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-25029</p>
</td>
<td rowspan="1" colspan="1">
<p>IBM Personal Communications 14.0.6 through 15.0.1 includes a Windows service
that is vulnerable to remote code execution (RCE) and local privilege escalation
(LPE). The vulnerability allows any unprivileged user with network access
to a target computer to run commands with full privileges in the context
of NT AUTHORITY\\SYSTEM. This allows for a low privileged attacker to move
laterally to affected systems and to escalate their privileges. IBM X-Force
ID: 281619.</p>
</td>
<td rowspan="1" colspan="1">
<p>9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-25029</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-25699</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Neutralization of Special Elements used in an OS Command ('OS
Command Injection') vulnerability in <a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">VideoWhisper.Com</a> VideoWhisper Live Streaming
Integration allows OS Command Injection.This issue affects VideoWhisper
Live Streaming Integration: from n/a through 5.5.15.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-25699</a></strong>
</p>
</td>
</tr>
</tbody>
</table>
<p>
<br>
</p>
<p><strong><u>OTHER VULNERABILITIES</u></strong>
</p>
<table>
<tbody>
<tr>
<th rowspan="1" colspan="1">
<p><strong>CVE Number</strong>
</p>
</th>
<th rowspan="1" colspan="1">
<p><strong>Description</strong>
</p>
</th>
<th rowspan="1" colspan="1">
<p><strong>Base Score</strong>
</p>
</th>
<th rowspan="1" colspan="1">
<p><strong>Reference</strong>
</p>
</th>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2693</p>
</td>
<td rowspan="1" colspan="1">
<p>The Link Whisper Free plugin for WordPress is vulnerable to PHP Object
Injection in all versions up to, and including, 0.7.1 via deserialization
of untrusted input of the 'mfn-page-items' post meta value. This makes
it possible for authenticated attackers, with contributor-level access
and above, to inject a PHP Object. No known POP chain is present in the
vulnerable plugin. If a POP chain is present via an additional plugin or
theme installed on the target system, it could allow the attacker to delete
arbitrary files, retrieve sensitive data, or execute code.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2693</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2342</p>
</td>
<td rowspan="1" colspan="1">
<p>The Appointment Booking Calendar — Simply Schedule Appointments Booking
Plugin plugin for WordPress is vulnerable to SQL Injection via the customer_id
parameter in all versions up to, and including, 1.6.7.7 due to insufficient
escaping on the user supplied parameter and lack of sufficient preparation
on the existing SQL query. This makes it possible for authenticated attackers,
with contributor access or higher, to append additional SQL queries into
already existing queries that can be used to extract sensitive information
from the database.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2342</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2341</p>
</td>
<td rowspan="1" colspan="1">
<p>The Appointment Booking Calendar — Simply Schedule Appointments Booking
Plugin plugin for WordPress is vulnerable to SQL Injection via the keys
parameter in all versions up to, and including, 1.6.7.7 due to insufficient
escaping on the user supplied parameter and lack of sufficient preparation
on the existing SQL query. This makes it possible for authenticated attackers,
with subscriber access and above, to append additional SQL queries into
already existing queries that can be used to extract sensitive information
from the database.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2341</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2125</p>
</td>
<td rowspan="1" colspan="1">
<p>The EnvíaloSimple: Email Marketing y Newsletters plugin for WordPress
is vulnerable to Cross-Site Request Forgery in all versions up to, and
including, 2.3. This is due to missing or incorrect nonce validation on
the gallery_add function. This makes it possible for unauthenticated attackers
to upload malicious files via a forged request granted they can trick a
site administrator into performing an action such as clicking on a link.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2125</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2018</p>
</td>
<td rowspan="1" colspan="1">
<p>The WP Activity Log Premium plugin for WordPress is vulnerable to SQL
Injection via the entry-&gt;roles parameter in all versions up to, and
including, 4.6.4 due to insufficient escaping on the user supplied parameter
and lack of sufficient preparation on the existing SQL query. This makes
it possible for authenticated attackers with subscriber privileges to append
additional SQL queries into already existing queries that can be used to
extract sensitive information from the database. One demonstrated attack
included the injection of a PHP Object.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2018</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1991</p>
</td>
<td rowspan="1" colspan="1">
<p>The RegistrationMagic – Custom Registration Forms, User Registration,
Payment, and User Login plugin for WordPress is vulnerable to privilege
escalation due to a missing capability check on the update_users_role()
function in all versions up to, and including, 5.3.0.0. This makes it possible
for authenticated attackers, with subscriber-level access and above, to
escalate their privileges to that of an administrator</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1991</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1990</p>
</td>
<td rowspan="1" colspan="1">
<p>The RegistrationMagic – Custom Registration Forms, User Registration,
Payment, and User Login plugin for WordPress is vulnerable to blind SQL
Injection via the ‘id’ parameter of the RM_Form shortcode in all versions
up to, and including, 5.3.1.0 due to insufficient escaping on the user
supplied parameter and lack of sufficient preparation on the existing SQL
query. This makes it possible for authenticated attackers, with contributor-level
access and above, to append additional SQL queries into already existing
queries that can be used to extract sensitive information from the database.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1990</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1974</p>
</td>
<td rowspan="1" colspan="1">
<p>The HT Mega – Absolute Addons For Elementor plugin for WordPress is vulnerable
to Directory Traversal in all versions up to, and including, 2.4.6 via
the render function. This makes it possible for authenticated attackers,
with contributor access or higher, to read the contents of arbitrary files
on the server, which can contain sensitive information.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1974</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1893</p>
</td>
<td rowspan="1" colspan="1">
<p>The Easy Property Listings plugin for WordPress is vulnerable to time-based
SQL Injection via the ‘property_status’ shortcode attribute in all versions
up to, and including, 3.5.2 due to insufficient escaping on the user supplied
parameter and lack of sufficient preparation on the existing SQL query.
This makes it possible for authenticated attackers, with contributor access
and above, to append additional SQL queries into already existing queries
that can be used to extract sensitive information from the database.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1893</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1315</p>
</td>
<td rowspan="1" colspan="1">
<p>The Classified Listing – Classified ads &amp; Business Directory Plugin
plugin for WordPress is vulnerable to Cross-Site Request Forgery in all
versions up to, and including, 3.0.4. This is due to missing or incorrect
nonce validation on the 'rtcl_update_user_account' function. This makes
it possible for unauthenticated attackers to change the administrator user's
password and email address via a forged request granted they can trick
a site administrator into performing an action such as clicking on a link.
This locks the administrator out of the site and prevents them from resetting
their password, while granting the attacker access to their account.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1315</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-6999</p>
</td>
<td rowspan="1" colspan="1">
<p>The Pods – Custom Content Types and Fields plugin for WordPress is vulnerable
to Remote Code Exxecution via shortcode in all versions up to, and including,
3.0.10 (with the exception of 2.7.31.2, 2.8.23.2, 2.9.19.2). This makes
it possible for authenticated attackers, with contributor level access
or higher, to execute code on the server.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-6999</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-6967</p>
</td>
<td rowspan="1" colspan="1">
<p>The Pods – Custom Content Types and Fields plugin for WordPress is vulnerable
to SQL Injection via shortcode in all versions up to, and including, 3.0.10
(with the exception of 2.7.31.2, 2.8.23.2, 2.9.19.2) due to insufficient
escaping on the user supplied parameter and lack of sufficient preparation
on the existing SQL query. This makes it possible for authenticated attackers,
with contributor level access or higher, to append additional SQL queries
into already existing queries that can be used to extract sensitive information
from the database.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-6967</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29993</p>
</td>
<td rowspan="1" colspan="1">
<p>Azure CycleCloud Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29993</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29988</p>
</td>
<td rowspan="1" colspan="1">
<p>SmartScreen Prompt Security Feature Bypass Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29988</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29985</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft OLE DB Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29985</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29984</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft OLE DB Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29984</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29983</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft OLE DB Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29983</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29982</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft OLE DB Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29982</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29053</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft Defender for IoT Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29053</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29048</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft OLE DB Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29048</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29047</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft OLE DB Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29047</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29046</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft OLE DB Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29046</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29044</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft OLE DB Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29044</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29043</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft ODBC Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29043</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28945</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft OLE DB Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28945</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28944</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft OLE DB Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28944</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28943</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft ODBC Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28943</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28942</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft OLE DB Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28942</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28941</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft ODBC Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28941</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28940</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft OLE DB Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28940</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28939</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft OLE DB Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28939</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28938</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft ODBC Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28938</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28937</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft ODBC Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28937</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28936</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft ODBC Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28936</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28935</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft ODBC Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28935</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28934</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft ODBC Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28934</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28933</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft ODBC Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28933</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28932</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft ODBC Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28932</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28931</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft ODBC Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28931</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28930</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft ODBC Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28930</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28929</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft ODBC Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28929</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28927</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft OLE DB Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28927</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28926</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft OLE DB Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28926</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28915</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft OLE DB Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28915</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28914</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft OLE DB Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28914</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28913</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft OLE DB Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28913</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28912</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft OLE DB Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28912</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28911</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft OLE DB Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28911</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28910</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft OLE DB Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28910</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28909</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft OLE DB Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28909</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28908</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft OLE DB Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28908</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28906</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft OLE DB Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28906</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26244</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft WDAC OLE DB Provider for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26244</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26214</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft WDAC SQL Server ODBC Driver Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26214</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26210</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft WDAC OLE DB Provider for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26210</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26205</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Routing and Remote Access Service (RRAS) Remote Code Execution
Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26205</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26200</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Routing and Remote Access Service (RRAS) Remote Code Execution
Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26200</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26179</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Routing and Remote Access Service (RRAS) Remote Code Execution
Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26179</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-21323</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft Defender for IoT Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-21323</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-20678</p>
</td>
<td rowspan="1" colspan="1">
<p>Remote Procedure Call Runtime Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-20678</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-21756</p>
</td>
<td rowspan="1" colspan="1">
<p>A improper neutralization of special elements used in an os command ('os
command injection') in Fortinet FortiSandbox version 4.4.0 through 4.4.3
and 4.2.0 through 4.2.6 and 4.0.0 through 4.0.4 allows attacker to execute
unauthorized code or commands via crafted requests..</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-21756</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-21755</p>
</td>
<td rowspan="1" colspan="1">
<p>A improper neutralization of special elements used in an os command ('os
command injection') in Fortinet FortiSandbox version 4.4.0 through 4.4.3
and 4.2.0 through 4.2.6 and 4.0.0 through 4.0.4 allows attacker to execute
unauthorized code or commands via crafted requests..</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-21755</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-1082</p>
</td>
<td rowspan="1" colspan="1">
<p>An remote attacker with low privileges can perform a command injection
which can lead to root access.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-1082</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2975</p>
</td>
<td rowspan="1" colspan="1">
<p>A race condition was identified through which privilege escalation was
possible in certain configurations.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2975</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27899</p>
</td>
<td rowspan="1" colspan="1">
<p>Self-Registration&nbsp;and Modify your own profile in User Admin Application
of NetWeaver AS Java does not enforce proper security requirements for
the content of the newly defined security answer. This can be leveraged
by an attacker to cause profound impact on confidentiality and low impact
on both integrity and availability.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27899</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31442</p>
</td>
<td rowspan="1" colspan="1">
<p>Redon Hub is a Roblox Product Delivery Bot, also known as a Hub. In all
hubs before version 1.0.2, all commands are capable of being ran by all
users, including admin commands. This allows users to receive products
for free and delete/create/update products/tags/etc. The only non-affected
command is <code>/products admin clear</code> as this was already programmed
for bot owners only. All users should upgrade to version 1.0.2 to receive
a patch.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31442</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-6523</p>
</td>
<td rowspan="1" colspan="1">
<p>Authorization Bypass Through User-Controlled Key vulnerability in ExtremePacs
Extreme XDS allows Authentication Abuse.This issue affects Extreme XDS:
before 3914.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-6523</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3217</p>
</td>
<td rowspan="1" colspan="1">
<p>The WP Directory Kit plugin for WordPress is vulnerable to SQL Injection
via the 'attribute_value' and 'attribute_id' parameters in all versions
up to, and including, 1.3.0 due to insufficient escaping on the user supplied
parameter and lack of sufficient preparation on the existing SQL query.
This makes it possible for authenticated attackers, with subscriber-level
access and above, to append additional SQL queries into already existing
queries that can be used to extract sensitive information from the database.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3217</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2115</p>
</td>
<td rowspan="1" colspan="1">
<p>The LearnPress – WordPress LMS Plugin plugin for WordPress is vulnerable
to Cross-Site Request Forgery in all versions up to, and including, 4.0.0.
This is due to missing or incorrect nonce validation on the filter_users
functions. This makes it possible for unauthenticated attackers to elevate
their privileges to that of a teacher via a forged request granted they
can trick a site administrator into performing an action such as clicking
on a link.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2115</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29672</p>
</td>
<td rowspan="1" colspan="1">
<p>Directory Traversal vulnerability in zly2006 Reden before v.0.2.514 allows
a remote attacker to execute arbitrary code via the DEBUG_RTC_REQUEST_SYNC_DATA
in KeyCallbacks.kt.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29672</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29192</p>
</td>
<td rowspan="1" colspan="1">
<p>gotortc is a camera streaming application. Versions 1.8.5 and prior are
vulnerable to Cross-Site Request Forgery. The <code>/api/config</code> endpoint
allows one to modify the existing configuration with user-supplied values.
While the API is only allowing <a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">localhost</a> to interact without authentication,
an attacker may be able to achieve that depending on how go2rtc is set
up on the upstream application, and given that this endpoint is not protected
against CSRF, it allows requests from any origin (e.g. a "drive-by" attack)
. The <code>exec</code> handler allows for any stream to execute arbitrary
commands. An attacker may add a custom stream through <code>api/config</code>,
which may lead to arbitrary command execution. In the event of a victim
visiting the server in question, their browser will execute the requests
against the go2rtc instance. Commit 8793c3636493c5efdda08f3b5ed5c6e1ea594fd9
adds a warning about secure API access.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29192</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2008</p>
</td>
<td rowspan="1" colspan="1">
<p>The Modal Popup Box – Popup Builder, Show Offers And News in Popup plugin
for WordPress is vulnerable to PHP Object Injection in all versions up
to, and including, 1.5.2 via deserialization of untrusted input in the
awl_modal_popup_box_shortcode function. This makes it possible for authenticated
attackers, with contributor-level access and above, to inject a PHP Object.
If a POP chain is present via an additional plugin or theme installed on
the target system, it could allow the attacker to delete arbitrary files,
retrieve sensitive data, or execute code.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2008</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2834</p>
</td>
<td rowspan="1" colspan="1">
<p>A Stored Cross-Site Scripting (XSS) vulnerability has been identified
in OpenText ArcSight Management Center and ArcSight Platform. The vulnerability
could be remotely exploited.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2834</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31277</p>
</td>
<td rowspan="1" colspan="1">
<p>Deserialization of Untrusted Data vulnerability in PickPlugins Product
Designer.This issue affects Product Designer: from n/a through 1.0.32.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>8.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31277</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28787</p>
</td>
<td rowspan="1" colspan="1">
<p>IBM Security Verify Access 10.0.0 through 10.0.7 and IBM Application Gateway
20.01 through 24.03 could allow a remote attacker to obtain highly sensitive
private information or cause a denial of service using a specially crafted
HTTP request. IBM X-Force ID: 286584.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28787</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-0081</p>
</td>
<td rowspan="1" colspan="1">
<p>
<br>NVIDIA NeMo framework for Ubuntu contains a vulnerability in tools/asr_webapp
where an attacker may cause an allocation of resources without limits or
throttling. A successful exploit of this vulnerability may lead to a server-side
denial of service.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>8.6</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-0081</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31851</p>
</td>
<td rowspan="1" colspan="1">
<p>A path traversal vulnerability exists in the Java version of CData Sync
&lt; 23.4.8843 when running using the embedded Jetty server, which could
allow an unauthenticated remote attacker to gain access to sensitive information
and perform limited actions.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.6</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31851</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31850</p>
</td>
<td rowspan="1" colspan="1">
<p>A path traversal vulnerability exists in the Java version of CData Arc
&lt; 23.4.8839 when running using the embedded Jetty server, which could
allow an unauthenticated remote attacker to gain access to sensitive information
and perform limited actions.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.6</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31850</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30249</p>
</td>
<td rowspan="1" colspan="1">
<p>Cloudburst Network provides network components used within Cloudburst
projects. A vulnerability in versions prior to <code>1.0.0.CR1-20240330.101522-15</code> impacts
publicly accessible software depending on the affected versions of Network
and allows an attacker to use Network as an amplification vector for a
UDP denial of service attack against a third party or as an attempt to
trigger service suspension of the host. All consumers of the library should
upgrade to at least version <code>1.0.0.CR1-20240330.101522-15</code> to
receive a fix. There are no known workarounds beyond updating the library.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.6</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30249</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-3454</p>
</td>
<td rowspan="1" colspan="1">
<p>Remote code execution (RCE) vulnerability in Brocade Fabric OS after v9.0
and before v9.2.0 could allow an attacker to execute arbitrary code and
use this to gain root access to the Brocade switch.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>8.6</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-3454</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-6964</p>
</td>
<td rowspan="1" colspan="1">
<p>The Gutenberg Blocks by Kadence Blocks – Page Builder Features plugin
for WordPress is vulnerable to Server-Side Request Forgery in all versions
up to, and including, 3.1.26 via the 'kadence_import_get_new_connection_data'
AJAX action. This makes it possible for authenticated attackers, with contributor-level
access and above, to make web requests to arbitrary locations originating
from the web application and can be used to query and modify information
from internal services.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-6964</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31370</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Neutralization of Special Elements used in an SQL Command ('SQL
Injection') vulnerability in CodeIsAwesome AIKit.This issue affects AIKit:
from n/a through 4.14.1.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>8.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31370</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31234</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Neutralization of Special Elements used in an SQL Command ('SQL
Injection') vulnerability in Sizam REHub Framework.This issue affects REHub
Framework: from n/a before 19.6.2.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>8.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31234</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31233</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Neutralization of Special Elements used in an SQL Command ('SQL
Injection') vulnerability in Sizam Rehub.This issue affects Rehub: from
n/a through 19.6.1.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>8.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31233</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-25699</p>
</td>
<td rowspan="1" colspan="1">
<p>
<br>There is a difficult to exploit improper authentication issue in the Home
application for Esri Portal for ArcGIS versions 10.8.1 through 11.2 on
Windows and Linux, and ArcGIS Enterprise 11.1 and below on Kubernetes which,
under unique circumstances, could potentially allow a remote, unauthenticated
attacker to compromise the confidentiality, integrity, and availability
of the software.
<br>
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>8.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-25699</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27191</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Control of Generation of Code ('Code Injection') vulnerability
in Inpersttion Slivery Extender allows Code Injection.This issue affects
Slivery Extender: from n/a through 1.0.2.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>8.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27191</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3313</p>
</td>
<td rowspan="1" colspan="1">
<p>SUBNET Solutions Inc. has identified vulnerabilities in third-party
<br>components used in PowerSYSTEM Server 2021 and Substation Server 2021.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>8.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3313</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29989</p>
</td>
<td rowspan="1" colspan="1">
<p>Azure Monitor Agent Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29989</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29050</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Cryptographic Services Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29050</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30191</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability has been identified in SCALANCE W1748-1 M12 (6GK5748-1GY01-0AA0),
SCALANCE W1748-1 M12 (6GK5748-1GY01-0TA0), SCALANCE W1788-1 M12 (6GK5788-1GY01-0AA0),
SCALANCE W1788-2 EEC M12 (6GK5788-2GY01-0TA0), SCALANCE W1788-2 M12 (6GK5788-2GY01-0AA0),
SCALANCE W1788-2IA M12 (6GK5788-2HY01-0AA0), SCALANCE W721-1 RJ45 (6GK5721-1FC00-0AA0),
SCALANCE W721-1 RJ45 (6GK5721-1FC00-0AB0), SCALANCE W722-1 RJ45 (6GK5722-1FC00-0AA0),
SCALANCE W722-1 RJ45 (6GK5722-1FC00-0AB0), SCALANCE W722-1 RJ45 (6GK5722-1FC00-0AC0),
SCALANCE W734-1 RJ45 (6GK5734-1FX00-0AA0), SCALANCE W734-1 RJ45 (6GK5734-1FX00-0AA6),
SCALANCE W734-1 RJ45 (6GK5734-1FX00-0AB0), SCALANCE W734-1 RJ45 (USA) (6GK5734-1FX00-0AB6),
SCALANCE W738-1 M12 (6GK5738-1GY00-0AA0), SCALANCE W738-1 M12 (6GK5738-1GY00-0AB0),
SCALANCE W748-1 M12 (6GK5748-1GD00-0AA0), SCALANCE W748-1 M12 (6GK5748-1GD00-0AB0),
SCALANCE W748-1 RJ45 (6GK5748-1FC00-0AA0), SCALANCE W748-1 RJ45 (6GK5748-1FC00-0AB0),
SCALANCE W761-1 RJ45 (6GK5761-1FC00-0AA0), SCALANCE W761-1 RJ45 (6GK5761-1FC00-0AB0),
SCALANCE W774-1 M12 EEC (6GK5774-1FY00-0TA0), SCALANCE W774-1 M12 EEC (6GK5774-1FY00-0TB0),
SCALANCE W774-1 RJ45 (6GK5774-1FX00-0AA0), SCALANCE W774-1 RJ45 (6GK5774-1FX00-0AA6),
SCALANCE W774-1 RJ45 (6GK5774-1FX00-0AB0), SCALANCE W774-1 RJ45 (6GK5774-1FX00-0AC0),
SCALANCE W774-1 RJ45 (USA) (6GK5774-1FX00-0AB6), SCALANCE W778-1 M12 (6GK5778-1GY00-0AA0),
SCALANCE W778-1 M12 (6GK5778-1GY00-0AB0), SCALANCE W778-1 M12 EEC (6GK5778-1GY00-0TA0),
SCALANCE W778-1 M12 EEC (USA) (6GK5778-1GY00-0TB0), SCALANCE W786-1 RJ45
(6GK5786-1FC00-0AA0), SCALANCE W786-1 RJ45 (6GK5786-1FC00-0AB0), SCALANCE
W786-2 RJ45 (6GK5786-2FC00-0AA0), SCALANCE W786-2 RJ45 (6GK5786-2FC00-0AB0),
SCALANCE W786-2 RJ45 (6GK5786-2FC00-0AC0), SCALANCE W786-2 SFP (6GK5786-2FE00-0AA0),
SCALANCE W786-2 SFP (6GK5786-2FE00-0AB0), SCALANCE W786-2IA RJ45 (6GK5786-2HC00-0AA0),
SCALANCE W786-2IA RJ45 (6GK5786-2HC00-0AB0), SCALANCE W788-1 M12 (6GK5788-1GD00-0AA0),
SCALANCE W788-1 M12 (6GK5788-1GD00-0AB0), SCALANCE W788-1 RJ45 (6GK5788-1FC00-0AA0),
SCALANCE W788-1 RJ45 (6GK5788-1FC00-0AB0), SCALANCE W788-2 M12 (6GK5788-2GD00-0AA0),
SCALANCE W788-2 M12 (6GK5788-2GD00-0AB0), SCALANCE W788-2 M12 EEC (6GK5788-2GD00-0TA0),
SCALANCE W788-2 M12 EEC (6GK5788-2GD00-0TB0), SCALANCE W788-2 M12 EEC (6GK5788-2GD00-0TC0),
SCALANCE W788-2 RJ45 (6GK5788-2FC00-0AA0), SCALANCE W788-2 RJ45 (6GK5788-2FC00-0AB0),
SCALANCE W788-2 RJ45 (6GK5788-2FC00-0AC0), SCALANCE WAM763-1 (6GK5763-1AL00-7DA0),
SCALANCE WAM766-1 (EU) (6GK5766-1GE00-7DA0), SCALANCE WAM766-1 (US) (6GK5766-1GE00-7DB0),
SCALANCE WAM766-1 EEC (EU) (6GK5766-1GE00-7TA0), SCALANCE WAM766-1 EEC
(US) (6GK5766-1GE00-7TB0), SCALANCE WUM763-1 (6GK5763-1AL00-3AA0), SCALANCE
WUM763-1 (6GK5763-1AL00-3DA0), SCALANCE WUM766-1 (EU) (6GK5766-1GE00-3DA0),
SCALANCE WUM766-1 (US) (6GK5766-1GE00-3DB0). This CVE refers to Scenario
3 "Override client’s security context" of CVE-2022-47522.\r
<br>\r
<br>Affected devices can be tricked into associating a newly negotiated, attacker-controlled,
security context with frames belonging to a victim. This could allow a
physically proximate attacker to decrypt frames meant for the victim.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30191</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-22423</p>
</td>
<td rowspan="1" colspan="1">
<p>yt-dlp is a youtube-dl fork with additional features and fixes. The patch
that addressed CVE-2023-40581 attempted to prevent RCE when using <code>--exec</code> with <code>%q</code> by
replacing double quotes with two double quotes. However, this escaping
is not sufficient, and still allows expansion of environment variables.
Support for output template expansion in <code>--exec</code>, along with
this vulnerable behavior, was added to <code>yt-dlp</code> in version 2021.04.11.
yt-dlp version 2024.04.09 fixes this issue by properly escaping <code>%</code>.
It replaces them with <code>%%cd:~,%</code>, a variable that expands to
nothing, leaving only the leading percent. It is recommended to upgrade
yt-dlp to version 2024.04.09 as soon as possible. Also, always be careful
when using <code>--exec</code>, because while this specific vulnerability
has been patched, using unvalidated input in shell commands is inherently
dangerous. For Windows users who are not able to upgrade, avoid using any
output template expansion in <code>--exec</code> other than <code>{}</code> (filepath);
if expansion in <code>--exec</code> is needed, verify the fields you are
using do not contain <code>"</code>, <code>|</code> or <code>&amp;</code>;
and/or instead of using <code>--exec</code>, write the info json and load
the fields from it instead.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-22423</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28235</p>
</td>
<td rowspan="1" colspan="1">
<p>Contao is an open source content management system. Starting in version
4.9.0 and prior to versions 4.13.40 and 5.3.4, when checking for broken
links on protected pages, Contao sends the cookie header to external urls
as well, the passed options for the http client are used for all requests.
Contao versions 4.13.40 and 5.3.4 have a patch for this issue. As a workaround,
disable crawling protected pages.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28235</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3446</p>
</td>
<td rowspan="1" colspan="1">
<p>A double free vulnerability was found in QEMU virtio devices (virtio-gpu,
virtio-serial-bus, virtio-crypto), where the mem_reentrancy_guard flag
insufficiently protects against DMA reentrancy issues. This issue could
allow a malicious privileged guest to crash the QEMU process on the host,
resulting in a denial of service or allow arbitrary code execution within
the context of the QEMU process on the host.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3446</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-0082</p>
</td>
<td rowspan="1" colspan="1">
<p>NVIDIA ChatRTX for Windows contains a vulnerability in the UI, where an
attacker can cause improper privilege management by sending open file requests
to the application. A successful exploit of this vulnerability might lead
to local escalation of privileges, information disclosure, and data tampering</p>
</td>
<td rowspan="1" colspan="1">
<p>8.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-0082</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31206</p>
</td>
<td rowspan="1" colspan="1">
<p>dectalk-tts is a Node package to interact with the aeiou Dectalk web API.
In <code>dectalk-tts@1.0.0</code>, network requests to the third-party API
are sent over HTTP, which is unencrypted. Unencrypted traffic can be easily
intercepted and modified by attackers. Anyone who uses the package could
be the victim of a man-in-the-middle (MITM) attack. The network request
was upgraded to HTTPS in version <code>1.0.1</code>. There are no workarounds,
but some precautions include not sending any sensitive information and
carefully verifying the API response before saving it.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31206</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-22053</p>
</td>
<td rowspan="1" colspan="1">
<p>A heap overflow vulnerability in IPSec component of Ivanti Connect Secure
(9.x
<br>22.x) and Ivanti Policy Secure allows an unauthenticated malicious user
to send specially crafted requests in-order-to crash the service thereby
causing a DoS attack or in certain conditions read contents from memory.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-22053</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29905</p>
</td>
<td rowspan="1" colspan="1">
<p>DIRAC is an interware, meaning a software framework for distributed computing.
Prior to version 8.0.41, during the proxy generation process (e.g., when
using <code>dirac-proxy-init</code>), it is possible for unauthorized users
on the same machine to gain read access to the proxy. This allows the user
to then perform any action that is possible with the original proxy. This
vulnerability only exists for a short period of time (sub-millsecond) during
the generation process. Version 8.0.41 contains a patch for the issue.
As a workaround, setting the <code>X509_USER_PROXY</code> environment variable
to a path that is inside a directory that is only readable to the current
user avoids the potential risk. After the file has been written, it can
be safely copied to the standard location (`/tmp/x509up_uNNNN`).</p>
</td>
<td rowspan="1" colspan="1">
<p>8.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29905</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-20670</p>
</td>
<td rowspan="1" colspan="1">
<p>Outlook for Windows Spoofing Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-20670</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-23671</p>
</td>
<td rowspan="1" colspan="1">
<p>A improper limitation of a pathname to a restricted directory ('path traversal')
in Fortinet FortiSandbox version 4.4.0 through 4.4.3 and 4.2.0 through
4.2.6 and 4.0.0 through 4.0.4 allows attacker to execute unauthorized code
or commands via crafted HTTP requests.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-23671</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-49134</p>
</td>
<td rowspan="1" colspan="1">
<p>A command execution vulnerability exists in the tddpd enable_test_mode
functionality of Tp-Link AC1350 Wireless MU-MIMO Gigabit Access Point (EAP225
V3) v5.1.0 Build 20220926 and Tp-Link N300 Wireless Access Point (EAP115
V4) v5.0.4 Build 20220216. A specially crafted series of network requests
can lead to arbitrary command execution. An attacker can send a sequence
of unauthenticated packets to trigger this vulnerability.This vulnerability
impacts <code>uclited</code> on the EAP115(V4) 5.0.4 Build 20220216 of the
N300 Wireless Gigabit Access Point.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-49134</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-49133</p>
</td>
<td rowspan="1" colspan="1">
<p>A command execution vulnerability exists in the tddpd enable_test_mode
functionality of Tp-Link AC1350 Wireless MU-MIMO Gigabit Access Point (EAP225
V3) v5.1.0 Build 20220926 and Tp-Link N300 Wireless Access Point (EAP115
V4) v5.0.4 Build 20220216. A specially crafted series of network requests
can lead to arbitrary command execution. An attacker can send a sequence
of unauthenticated packets to trigger this vulnerability.This vulnerability
impacts <code>uclited</code> on the EAP225(V3) 5.1.0 Build 20220926 of the
AC1350 Wireless MU-MIMO Gigabit Access Point.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-49133</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2224</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Limitation of a Pathname to a Restricted Directory (‘Path Traversal’)
vulnerability in the UpdateServer component of Bitdefender GravityZone
allows an attacker to execute arbitrary code on vulnerable instances. This
issue affects the following products that include the vulnerable component:
<br>
<br>Bitdefender Endpoint Security for Linux version 7.0.5.200089
<br>Bitdefender Endpoint Security for Windows version 7.9.9.380
<br>GravityZone Control Center (On Premises) version 6.36.1</p>
</td>
<td rowspan="1" colspan="1">
<p>8.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2224</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2223</p>
</td>
<td rowspan="1" colspan="1">
<p>An Incorrect Regular Expression vulnerability in Bitdefender GravityZone
Update Server allows an attacker to cause a Server Side Request Forgery
and reconfigure the relay. This issue affects the following products that
include the vulnerable component:&nbsp;
<br>
<br>Bitdefender Endpoint Security for Linux version 7.0.5.200089
<br>Bitdefender Endpoint Security for&nbsp; Windows version 7.9.9.380
<br>GravityZone Control Center (On Premises) version 6.36.1</p>
</td>
<td rowspan="1" colspan="1">
<p>8.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2223</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30264</p>
</td>
<td rowspan="1" colspan="1">
<p>Typebot is an open-source chatbot builder. A reflected cross-site scripting
(XSS) in the sign-in page of <a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">typebot.io</a> prior to version 2.24.0 may
allow an attacker to hijack a user's account. The sign-in page takes the <code>redirectPath</code> parameter
from the URL. If a user clicks on a link where the <code>redirectPath</code> parameter
has a javascript scheme, the attacker that crafted the link may be able
to execute arbitrary JavaScript with the privileges of the user. Version
2.24.0 contains a patch for this issue.</p>
</td>
<td rowspan="1" colspan="1">
<p>8.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30264</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28925</p>
</td>
<td rowspan="1" colspan="1">
<p>Secure Boot Security Feature Bypass Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28925</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26240</p>
</td>
<td rowspan="1" colspan="1">
<p>Secure Boot Security Feature Bypass Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26240</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26189</p>
</td>
<td rowspan="1" colspan="1">
<p>Secure Boot Security Feature Bypass Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26189</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26180</p>
</td>
<td rowspan="1" colspan="1">
<p>Secure Boot Security Feature Bypass Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26180</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-0172</p>
</td>
<td rowspan="1" colspan="1">
<p>Dell PowerEdge Server BIOS and Dell Precision Rack BIOS contain an improper
privilege management security vulnerability. An unauthenticated local attacker
could potentially exploit this vulnerability, leading to privilege escalation.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-0172</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29061</p>
</td>
<td rowspan="1" colspan="1">
<p>Secure Boot Security Feature Bypass Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29061</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29052</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Storage Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29052</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28920</p>
</td>
<td rowspan="1" colspan="1">
<p>Secure Boot Security Feature Bypass Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28920</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28907</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft Brokering File System Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28907</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28905</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft Brokering File System Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28905</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28904</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft Brokering File System Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28904</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26257</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft Excel Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26257</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26256</p>
</td>
<td rowspan="1" colspan="1">
<p>libarchive Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26256</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26245</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows SMB Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26245</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26241</p>
</td>
<td rowspan="1" colspan="1">
<p>Win32k Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26241</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26239</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Telephony Server Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26239</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26237</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Defender Credential Guard Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26237</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26235</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Update Stack Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26235</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26230</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Telephony Server Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26230</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26229</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows CSC Service Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26229</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26228</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Cryptographic Services Security Feature Bypass Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26228</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26218</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Kernel Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26218</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26211</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Remote Access Connection Manager Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26211</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26175</p>
</td>
<td rowspan="1" colspan="1">
<p>Secure Boot Security Feature Bypass Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26175</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26158</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft Install Service Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26158</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-21447</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Authentication Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-21447</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-20693</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Kernel Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-20693</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26275</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability has been identified in Parasolid V35.1 (All versions &lt;
V35.1.254), Parasolid V36.0 (All versions &lt; V36.0.207), Parasolid V36.1
(All versions &lt; V36.1.147). The affected applications contain an out
of bounds read past the end of an allocated structure while parsing specially
crafted X_T files. This could allow an attacker to execute code in the
context of the current process.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26275</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29748</p>
</td>
<td rowspan="1" colspan="1">
<p>there is a possible way to bypass due to a logic error in the code. This
could lead to local escalation of privilege with no additional execution
privileges needed. User interaction is needed for exploitation.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29748</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31083</p>
</td>
<td rowspan="1" colspan="1">
<p>A use-after-free vulnerability was found in the ProcRenderAddGlyphs()
function of Xorg servers. This issue occurs when AllocateGlyph() is called
to store new glyphs sent by the client to the X server, potentially resulting
in multiple entries pointing to the same non-refcounted glyphs. Consequently,
ProcRenderAddGlyphs() may free a glyph, leading to a use-after-free scenario
when the same glyph pointer is subsequently accessed. This flaw allows
an authenticated attacker to execute arbitrary code on the system by sending
a specially crafted request.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31083</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3299</p>
</td>
<td rowspan="1" colspan="1">
<p>Out-Of-Bounds Write, Use of Uninitialized Resource and Use-After-Free
vulnerabilities exist in the file reading procedure in eDrawings from Release
SOLIDWORKS 2023 through Release SOLIDWORKS 2024. These vulnerabilities
could allow an attacker to execute arbitrary code while opening a specially
crafted SLDDRW or SLDPRT file. NOTE: this vulnerability was SPLIT from
CVE-2024-1847.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3299</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3298</p>
</td>
<td rowspan="1" colspan="1">
<p>Out-Of-Bounds Write and Type Confusion vulnerabilities exist in the file
reading procedure in eDrawings from Release SOLIDWORKS 2023 through Release
SOLIDWORKS 2024. These vulnerabilities could allow an attacker to execute
arbitrary code while opening a specially crafted DWG or DXF. NOTE: this
vulnerability was SPLIT from CVE-2024-1847.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3298</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-0394</p>
</td>
<td rowspan="1" colspan="1">
<p>Rapid7 Minerva Armor versions below 4.5.5 suffer from a privilege escalation
vulnerability whereby an authenticated attacker can elevate privileges
and execute arbitrary code with SYSTEM privilege.&nbsp; The vulnerability
is caused by the product's implementation of OpenSSL's`OPENSSLDIR` parameter
where it is set to a path accessible to low-privileged users.&nbsp; The
vulnerability has been remediated and fixed in version 4.5.5.&nbsp;</p>
</td>
<td rowspan="1" colspan="1">
<p>7.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-0394</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31457</p>
</td>
<td rowspan="1" colspan="1">
<p>gin-vue-admin is a backstage management system based on vue and gin, which
separates the front and rear of the full stack. gin-vue-admin pseudoversion
0.0.0-20240407133540-7bc7c3051067, corresponding to version 2.6.1, has
a code injection vulnerability in the backend. In the Plugin System -&gt;
Plugin Template feature, an attacker can perform directory traversal by
manipulating the <code>plugName</code> parameter. They can create specific
folders such as <code>api</code>, <code>config</code>, <code>global</code>, <code>model</code>, <code>router</code>, <code>service</code>,
and <code>main.go</code> function within the specified traversal directory.
Moreover, the Go files within these folders can have arbitrary code inserted
based on a specific PoC parameter. The main reason for the existence of
this vulnerability is the controllability of the PlugName field within
the struct. Pseudoversion 0.0.0-20240409100909-b1b7427c6ea6, corresponding
to commit b1b7427c6ea6c7a027fa188c6be557f3795e732b, contains a patch for
the issue. As a workaround, one may manually use a filtering method available
in the GitHub Security Advisory to rectify the directory traversal problem.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31457</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-25646</p>
</td>
<td rowspan="1" colspan="1">
<p>Due to improper validation,&nbsp;SAP BusinessObject Business Intelligence
Launch Pad allows an authenticated attacker to access operating system
information using crafted document. On successful exploitation there could
be a considerable impact on confidentiality of the application.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>7.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-25646</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30263</p>
</td>
<td rowspan="1" colspan="1">
<p>macro-pdfviewer is a PDF Viewer Macro for XWiki using Mozilla pdf.js.
Users with edit rights can access restricted PDF attachments using the
PDF Viewer macro, just by passing the attachment URL as the value of the
``file`` parameter. Users with view rights can access restricted PDF attachments
if they are shown on public pages where the PDF Viewer macro is called
using the attachment URL instead of its reference. This vulnerability has
been patched in version 2.5.1.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30263</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3046</p>
</td>
<td rowspan="1" colspan="1">
<p>In Eclipse Kura LogServlet component included in versions 5.0.0 to 5.4.1,
a specifically crafted request to the servlet can allow an unauthenticated
user to retrieve the device logs. Also, downloaded logs may be used by
an attacker to perform privilege escalation by using the session id of
an authenticated user reported in logs.
<br>
<br>
<br>
<br>
<br>This issue affects org.eclipse.kura:org.eclipse.kura.web2 version range
[2.0.600, 2.4.0], which is included in Eclipse Kura version range [5.0.0,
5.4.1]
<br>
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>7.6</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3046</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31978</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability has been identified in SINEC NMS (All versions &lt; V2.0
SP2). Affected devices allow authenticated users to export monitoring data.
The corresponding API endpoint is susceptible to path traversal and could
allow an authenticated attacker to download files from the file system.
Under certain circumstances the downloaded files are deleted from the file
system.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.6</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31978</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31260</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Neutralization of Special Elements used in an SQL Command ('SQL
Injection') vulnerability in WisdmLabs Edwiser Bridge.This issue affects
Edwiser Bridge: from n/a through 3.0.2.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>7.6</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31260</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31241</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Neutralization of Special Elements used in an SQL Command ('SQL
Injection') vulnerability in ThimPress LearnPress Export Import.This issue
affects LearnPress Export Import: from n/a through 4.0.3.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>7.6</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31241</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31210</p>
</td>
<td rowspan="1" colspan="1">
<p>WordPress is an open publishing platform for the Web. It's possible for
a file of a type other than a zip file to be submitted as a new plugin
by an administrative user on the Plugins -&gt; Add New -&gt; Upload Plugin
screen in WordPress. If FTP credentials are requested for installation
(in order to move the file into place outside of the <code>uploads</code> directory)
then the uploaded file remains temporary available in the Media Library
despite it not being allowed. If the <code>DISALLOW_FILE_EDIT</code> constant
is set to <code>true</code> on the site <em>and</em> FTP credentials are required
when uploading a new theme or plugin, then this technically allows an RCE
when the user would otherwise have no means of executing arbitrary PHP
code. This issue <em>only</em> affects Administrator level users on single
site installations, and Super Admin level users on Multisite installations
where it's otherwise expected that the user does not have permission to
upload or execute arbitrary PHP code. Lower level users are not affected.
Sites where the <code>DISALLOW_FILE_MODS</code> constant is set to <code>true</code> are
not affected. Sites where an administrative user either does not need to
enter FTP credentials or they have access to the valid FTP credentials,
are not affected. The issue was fixed in WordPress 6.4.3 on January 30,
2024 and backported to versions 6.3.3, 6.2.4, 6.1.5, 6.0.7, 5.9.9, 5.8.9,
5.7.11, 5.6.13, 5.5.14, 5.4.15, 5.3.17, 5.2.20, 5.1.18, 5.0.21, 4.9.25,
2.8.24, 4.7.28, 4.6.28, 4.5.31, 4.4.32, 4.3.33, 4.2.37, and 4.1.40. A workaround
is available. If the <code>DISALLOW_FILE_MODS</code> constant is defined
as <code>true</code> then it will not be possible for any user to upload
a plugin and therefore this issue will not be exploitable.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.6</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31210</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2501</p>
</td>
<td rowspan="1" colspan="1">
<p>The Hubbub Lite – Fast, Reliable Social Sharing Buttons plugin for WordPress
is vulnerable to PHP Object Injection in all versions up to, and including,
1.33.1 via deserialization of untrusted input via the 'dpsp_maybe_unserialize'
function. This makes it possible for authenticated attackers, with contributor
access and above, to inject a PHP Object. No POP chain is present in the
vulnerable plugin. If a POP chain is present via an additional plugin or
theme installed on the target system, it could allow the attacker to delete
arbitrary files, retrieve sensitive data, or execute code.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2501</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1934</p>
</td>
<td rowspan="1" colspan="1">
<p>The WP Compress – Image Optimizer plugin for WordPress is vulnerable to
unauthorized modification of data due to a missing capability check on
the 'wps_local_compress::__construct' function in all versions up to, and
including, 6.11.10. This makes it possible for unauthenticated attackers
to reset the CDN region and set a malicious URL to deliver images.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1934</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1792</p>
</td>
<td rowspan="1" colspan="1">
<p>The CMB2 plugin for WordPress is vulnerable to PHP Object Injection in
all versions up to, and including, 2.10.1 via deserialization of untrusted
input from the text_datetime_timestamp_timezone field. This makes it possible
for authenticated attackers, with contributor access or higher, to inject
a PHP Object. No POP chain is present in the vulnerable plugin. If a POP
chain is present via an additional plugin or theme installed on the target
system, it could allow the attacker to delete arbitrary files, retrieve
sensitive data, or execute code. Please note that the plugin is a developer
toolkit. For the vulnerability to become exploitable, the presence of a
metabox activation in your code (via functions.php for example) is required.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1792</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1308</p>
</td>
<td rowspan="1" colspan="1">
<p>The WooCommerce Cloak Affiliate Links plugin for WordPress is vulnerable
to unauthorized modification of data due to a missing capability check
on the 'permalink_settings_save' function in all versions up to, and including,
1.0.33. This makes it possible for unauthenticated attackers to modify
the affiliate permalink base, driving traffic to malicious sites via the
plugin's affiliate links.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1308</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-7046</p>
</td>
<td rowspan="1" colspan="1">
<p>The WP Encryption – One Click Free SSL Certificate &amp; SSL / HTTPS Redirect
to Force HTTPS, SSL Score plugin for WordPress is vulnerable to Sensitive
Information Exposure in all versions up to, and including, 7.0 via exposed
Private key files. This makes it possible for unauthenticated attackers
to extract sensitive data including TLS Certificate Private Keys</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-7046</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29045</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft OLE DB Driver for SQL Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29045</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28896</p>
</td>
<td rowspan="1" colspan="1">
<p>Secure Boot Security Feature Bypass Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28896</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26254</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft Virtual Machine Bus (VMBus) Denial of Service Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26254</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26248</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Kerberos Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26248</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26219</p>
</td>
<td rowspan="1" colspan="1">
<p>HTTP.sys Denial of Service Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26219</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26215</p>
</td>
<td rowspan="1" colspan="1">
<p>DHCP Server Service Denial of Service Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26215</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26212</p>
</td>
<td rowspan="1" colspan="1">
<p>DHCP Server Service Denial of Service Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26212</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-48724</p>
</td>
<td rowspan="1" colspan="1">
<p>A memory corruption vulnerability exists in the web interface functionality
of Tp-Link AC1350 Wireless MU-MIMO Gigabit Access Point (EAP225 V3) v5.1.0
Build 20220926. A specially crafted HTTP POST request can lead to denial
of service of the device's web interface. An attacker can send an unauthenticated
HTTP POST request to trigger this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-48724</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-41677</p>
</td>
<td rowspan="1" colspan="1">
<p>A insufficiently protected credentials in Fortinet FortiProxy 7.4.0, 7.2.0
through 7.2.6, 7.0.0 through 7.0.12, 2.0.0 through 2.0.13, 1.2.0 through
1.2.13, 1.1.0 through 1.1.6, 1.0.0 through 1.0.7, Fortinet FortiOS 7.4.0
through 7.4.1, 7.2.0 through 7.2.6, 7.0.0 through 7.0.12, 6.4.0 through
6.4.14, 6.2.0 through 6.2.15, 6.0.0 through 6.0.17 allows attacker to execute
unauthorized code or commands via targeted social engineering attack</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-41677</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-22328</p>
</td>
<td rowspan="1" colspan="1">
<p>IBM Maximo Application Suite 8.10 and 8.11 could allow a remote attacker
to traverse directories on the system. An attacker could send a specially
crafted URL request containing "dot dot" sequences (/../) to view arbitrary
files on the system. IBM X-Force ID: 279950.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-22328</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27912</p>
</td>
<td rowspan="1" colspan="1">
<p>A denial of service vulnerability was reported in some Lenovo Printers
that could allow an attacker to cause the device to crash by sending crafted
LPD packets.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27912</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27911</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was reported in some Lenovo Printers that could allow
an unauthenticated attacker to obtain the administrator password.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27911</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-22052</p>
</td>
<td rowspan="1" colspan="1">
<p>A null pointer dereference vulnerability in IPSec component of Ivanti
Connect Secure (9.x, 22.x) and Ivanti Policy Secure allows an unauthenticated
malicious user to send specially crafted requests in-order-to crash the
service thereby causing a DoS attack</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-22052</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30250</p>
</td>
<td rowspan="1" colspan="1">
<p>Astro-Shield is an integration to enhance website security with SubResource
Integrity hashes, Content-Security-Policy headers, and other techniques.
Versions from 1.2.0 to 1.3.1 of Astro-Shield allow bypass to the allow-lists
for cross-origin resources by introducing valid <code>integrity</code> attributes
to the injected code. This implies that the injected SRI hash would be
added to the generated CSP header, which would lead the browser to believe
that the injected resource is legit. This vulnerability is patched in version
1.3.2.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30250</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28871</p>
</td>
<td rowspan="1" colspan="1">
<p>LibHTP is a security-aware parser for the HTTP protocol and the related
bits and pieces. Version 0.5.46 may parse malformed request traffic, leading
to excessive CPU usage. Version 0.5.47 contains a patch for the issue.
No known workarounds are available.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28871</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27919</p>
</td>
<td rowspan="1" colspan="1">
<p>Envoy is a cloud-native, open-source edge and service proxy. In versions
1.29.0 and 1.29.1, theEnvoy HTTP/2 protocol stack is vulnerable to the
flood of CONTINUATION frames. Envoy's HTTP/2 codec does not reset a request
when header map limits have been exceeded. This allows an attacker to send
an sequence of CONTINUATION frames without the END_HEADERS bit set causing
unlimited memory consumption. This can lead to denial of service through
memory exhaustion. Users should upgrade to versions 1.29.2 to mitigate
the effects of the CONTINUATION flood. Note that this vulnerability is
a regression in Envoy version 1.29.0 and 1.29.1 only. As a workaround,
downgrade to version 1.28.1 or earlier or disable HTTP/2 protocol for downstream
connections.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27919</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-22189</p>
</td>
<td rowspan="1" colspan="1">
<p>quic-go is an implementation of the QUIC protocol in Go. Prior to version
0.42.0, an attacker can cause its peer to run out of memory sending a large
number of <code>NEW_CONNECTION_ID</code> frames that retire old connection
IDs. The receiver is supposed to respond to each retirement frame with
a <code>RETIRE_CONNECTION_ID</code> frame. The attacker can prevent the receiver
from sending out (the vast majority of) these <code>RETIRE_CONNECTION_ID</code> frames
by collapsing the peers congestion window (by selectively acknowledging
received packets) and by manipulating the peer's RTT estimate. Version
0.42.0 contains a patch for the issue. No known workarounds are available.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-22189</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-36644</p>
</td>
<td rowspan="1" colspan="1">
<p>Incorrect Access Control in ITB-GmbH TradePro v9.5, allows remote attackers
to receive all order confirmations from the online shop via the printmail
plugin.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-36644</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-36643</p>
</td>
<td rowspan="1" colspan="1">
<p>Incorrect Access Control in ITB-GmbH TradePro v9.5, allows remote attackers
to receive all orders from the online shop via oordershow component in
customer function.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-36643</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30265</p>
</td>
<td rowspan="1" colspan="1">
<p>Collabora Online is a collaborative online office suite based on LibreOffice
technology. Any deployment of voilà dashboard allow local file inclusion.
Any file on a filesystem that is readable by the user that runs the voilà
dashboard server can be downloaded by someone with network access to the
server. Whether this still requires authentication depends on how voilà
is deployed. This issue has been patched in 0.2.17, 0.3.8, 0.4.4 and 0.5.6.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30265</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28870</p>
</td>
<td rowspan="1" colspan="1">
<p>Suricata is a network Intrusion Detection System, Intrusion Prevention
System and Network Security Monitoring engine developed by the OISF and
the Suricata community. When parsing an overly long SSH banner, Suricata
can use excessive CPU resources, as well as cause excessive logging volume
in alert records. This issue has been patched in versions 6.0.17 and 7.0.4.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28870</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-0335</p>
</td>
<td rowspan="1" colspan="1">
<p>
<br>ABB has internally identified a vulnerability in the ABB VPNI feature
of the S+ Control API component which may
<br>be used by several Symphony Plus products (e.g., S+ Operations, S+ Engineering
and S+ Analyst)
<br>
<br>This issue affects Symphony Plus S+ Operations: from 3..0;0 through 3.3
SP1 RU4, from 2.1;0 through 2.1 SP2 RU3, from 2.0;0 through 2.0 SP6 TC6;
Symphony Plus S+ Engineering: from 2.1 through 2.3 RU3; Symphony Plus S+
Analyst: from 7.0.0.0 through 7.2.0.2.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-0335</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-20348</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability in the Out-of-Band (OOB) Plug and Play (PnP) feature of
Cisco Nexus Dashboard Fabric Controller (NDFC) could allow an unauthenticated,
remote attacker to read arbitrary files.\r
<br>\r This vulnerability is due to an unauthenticated provisioning web server.
An attacker could exploit this vulnerability through direct web requests
to the provisioning server. A successful exploit could allow the attacker
to read sensitive files in the PnP container that could facilitate further
attacks on the PnP infrastructure.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-20348</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-20281</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability in the web-based management interface of Cisco Nexus Dashboard
and Cisco Nexus Dashboard hosted services could allow an unauthenticated,
remote attacker to conduct a cross-site request forgery (CSRF) attack on
an affected system.\r
<br>\r This vulnerability is due to insufficient CSRF protections for the
web-based management interface on an affected system. An attacker could
exploit this vulnerability by persuading a user to click a malicious link.
A successful exploit could allow the attacker to perform arbitrary actions
with the privilege level of the affected user. If the affected user has
administrative privileges, these actions could include modifying the system
configuration and creating new privileged accounts.\r
<br>\r Note: There are internal security mechanisms in place that limit the
scope of this exploit, reducing the Security Impact Rating of this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-20281</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2879</p>
</td>
<td rowspan="1" colspan="1">
<p>The LayerSlider plugin for WordPress is vulnerable to SQL Injection via
the ls_get_popup_markup action in versions 7.9.11 and 7.10.0 due to insufficient
escaping on the user supplied parameter and lack of sufficient preparation
on the existing SQL query. This makes it possible for unauthenticated attackers
to append additional SQL queries into already existing queries that can
be used to extract sensitive information from the database.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2879</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26194</p>
</td>
<td rowspan="1" colspan="1">
<p>Secure Boot Security Feature Bypass Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26194</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-49074</p>
</td>
<td rowspan="1" colspan="1">
<p>A denial of service vulnerability exists in the TDDP functionality of
Tp-Link AC1350 Wireless MU-MIMO Gigabit Access Point (EAP225 V3) v5.1.0
Build 20220926. A specially crafted series of network requests can lead
to reset to factory settings. An attacker can send a sequence of unauthenticated
packets to trigger this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-49074</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3116</p>
</td>
<td rowspan="1" colspan="1">
<p>pgAdmin &lt;= 8.4 is affected by a Remote Code Execution (RCE) vulnerability
through the validate binary path API. This vulnerability allows attackers
to execute arbitrary code on the server hosting PGAdmin, posing a severe
risk to the database management system's integrity and the security of
the underlying data.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3116</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29063</p>
</td>
<td rowspan="1" colspan="1">
<p>Azure AI Search Information Disclosure Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29063</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26232</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft Message Queuing (MSMQ) Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26232</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26216</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows File Server Resource Management Service Elevation of Privilege
Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26216</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-21409</p>
</td>
<td rowspan="1" colspan="1">
<p>.NET, .NET Framework, and Visual Studio Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-21409</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1233</p>
</td>
<td rowspan="1" colspan="1">
<p>A flaw was found in` JwtValidator.resolvePublicKey` in JBoss EAP, where
the validator checks jku and sends a HTTP request. During this process,
no whitelisting or other filtering behavior is performed on the destination
URL address, which may result in a server-side request forgery (SSRF) vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1233</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3439</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Prison Management System 1.0.
It has been classified as critical. Affected is an unknown function of
the file /Account/login.php. The manipulation leads to sql injection. It
is possible to launch the attack remotely. The exploit has been disclosed
to the public and may be used. The identifier of this vulnerability is
VDB-259692.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3439</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3438</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Prison Management System 1.0
and classified as critical. This issue affects some unknown processing
of the file /Admin/login.php. The manipulation leads to sql injection.
The attack may be initiated remotely. The exploit has been disclosed to
the public and may be used. The associated identifier of this vulnerability
is VDB-259691.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3438</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3413</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability has been found in SourceCodester Human Resource Information
System 1.0 and classified as critical. This vulnerability affects unknown
code of the file initialize/login_process.php. The manipulation of the
argument hr_email/hr_password leads to sql injection. The attack can be
initiated remotely. The exploit has been disclosed to the public and may
be used. VDB-259582 is the identifier assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3413</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3376</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability classified as critical has been found in SourceCodester
Computer Laboratory Management System 1.0. This affects an unknown part
of the file config.php. The manipulation of the argument url leads to execution
after redirect. It is possible to initiate the attack remotely. The exploit
has been disclosed to the public and may be used. The identifier VDB-259497
was assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3376</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3363</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Online Library System 1.0.
It has been classified as critical. This affects an unknown part of the
file admin/borrowed/index.php. The manipulation of the argument BookPublisher/BookTitle
leads to sql injection. It is possible to initiate the attack remotely.
The exploit has been disclosed to the public and may be used. The associated
identifier of this vulnerability is VDB-259467.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3363</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3362</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Online Library System 1.0
and classified as critical. Affected by this issue is some unknown functionality
of the file admin/books/controller.php. The manipulation of the argument
IBSN leads to sql injection. The attack may be launched remotely. The exploit
has been disclosed to the public and may be used. VDB-259466 is the identifier
assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3362</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3361</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability has been found in SourceCodester Online Library System
1.0 and classified as critical. Affected by this vulnerability is an unknown
functionality of the file admin/books/deweydecimal.php. The manipulation
of the argument category leads to sql injection. The attack can be launched
remotely. The exploit has been disclosed to the public and may be used.
The identifier VDB-259465 was assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3361</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3360</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability, which was classified as critical, was found in SourceCodester
Online Library System 1.0. Affected is an unknown function of the file
admin/books/index.php. The manipulation of the argument id leads to sql
injection. It is possible to launch the attack remotely. The exploit has
been disclosed to the public and may be used. The identifier of this vulnerability
is VDB-259464.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3360</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3359</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability, which was classified as critical, has been found in SourceCodester
Online Library System 1.0. This issue affects some unknown processing of
the file admin/login.php. The manipulation of the argument user_email leads
to sql injection. The attack may be initiated remotely. The exploit has
been disclosed to the public and may be used. The associated identifier
of this vulnerability is VDB-259463.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3359</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3356</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Aplaya Beach Resort Online
Reservation System 1.0. It has been rated as critical. Affected by this
issue is some unknown functionality of the file admin/mod_settings/controller.php?action=add.
The manipulation of the argument type leads to sql injection. The attack
may be launched remotely. The exploit has been disclosed to the public
and may be used. The identifier of this vulnerability is VDB-259460.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3356</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3355</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Aplaya Beach Resort Online
Reservation System 1.0. It has been declared as critical. Affected by this
vulnerability is an unknown functionality of the file admin/mod_users/controller.php?action=add.
The manipulation of the argument name leads to sql injection. The attack
can be launched remotely. The exploit has been disclosed to the public
and may be used. The associated identifier of this vulnerability is VDB-259459.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3355</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3354</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Aplaya Beach Resort Online
Reservation System 1.0. It has been classified as critical. Affected is
an unknown function of the file admin/mod_users/index.php. The manipulation
of the argument id leads to sql injection. It is possible to launch the
attack remotely. The exploit has been disclosed to the public and may be
used. VDB-259458 is the identifier assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3354</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3353</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Aplaya Beach Resort Online
Reservation System 1.0 and classified as critical. This issue affects some
unknown processing of the file admin/mod_reports/index.php. The manipulation
of the argument categ/end leads to sql injection. The attack may be initiated
remotely. The exploit has been disclosed to the public and may be used.
The identifier VDB-259457 was assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3353</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3352</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability has been found in SourceCodester Aplaya Beach Resort Online
Reservation System 1.0 and classified as critical. This vulnerability affects
unknown code of the file admin/mod_comments/index.php. The manipulation
of the argument id leads to sql injection. The attack can be initiated
remotely. The exploit has been disclosed to the public and may be used.
The identifier of this vulnerability is VDB-259456.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3352</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3351</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability, which was classified as critical, was found in SourceCodester
Aplaya Beach Resort Online Reservation System 1.0. This affects an unknown
part of the file admin/mod_roomtype/index.php. The manipulation of the
argument id leads to sql injection. It is possible to initiate the attack
remotely. The exploit has been disclosed to the public and may be used.
The associated identifier of this vulnerability is VDB-259455.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3351</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3350</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability, which was classified as critical, has been found in SourceCodester
Aplaya Beach Resort Online Reservation System 1.0. Affected by this issue
is some unknown functionality of the file admin/mod_room/index.php. The
manipulation of the argument id leads to sql injection. The attack may
be launched remotely. The exploit has been disclosed to the public and
may be used. VDB-259454 is the identifier assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3350</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3349</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability classified as critical was found in SourceCodester Aplaya
Beach Resort Online Reservation System 1.0. Affected by this vulnerability
is an unknown functionality of the file admin/login.php. The manipulation
of the argument email leads to sql injection. The attack can be launched
remotely. The exploit has been disclosed to the public and may be used.
The identifier VDB-259453 was assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3349</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3348</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability classified as critical has been found in SourceCodester
Aplaya Beach Resort Online Reservation System 1.0. Affected is an unknown
function of the file booking/index.php. The manipulation of the argument
log_email/log_pword leads to sql injection. It is possible to launch the
attack remotely. The exploit has been disclosed to the public and may be
used. The identifier of this vulnerability is VDB-259452.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3348</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3347</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Airline Ticket Reservation
System 1.0. It has been rated as critical. This issue affects some unknown
processing of the file activate_jet_details_form_handler.php. The manipulation
of the argument jet_id leads to sql injection. The attack may be initiated
remotely. The exploit has been disclosed to the public and may be used.
The associated identifier of this vulnerability is VDB-259451.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3347</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31220</p>
</td>
<td rowspan="1" colspan="1">
<p>Sunshine is a self-hosted game stream host for Moonlight. Starting in
version 0.16.0 and prior to version 0.18.0, an attacker may be able to
remotely read arbitrary files without authentication due to a path traversal
vulnerability. Users who exposed the Sunshine configuration web user interface
outside of <a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">localhost</a> may
be affected, depending on firewall configuration. To exploit vulnerability,
attacker could make an http/s request to the <code>node_modules</code> endpoint
if user exposed Sunshine config web server to internet or attacker is on
the LAN. Version 0.18.0 contains a patch for this issue. As a workaround,
one may block access to Sunshine via firewall.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31220</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31082</p>
</td>
<td rowspan="1" colspan="1">
<p>A heap-based buffer over-read vulnerability was found in the <a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">X.org</a> server's
ProcAppleDRICreatePixmap() function. This issue occurs when byte-swapped
length values are used in replies, potentially leading to memory leakage
and segmentation faults, particularly when triggered by a client with a
different endianness. This vulnerability could be exploited by an attacker
to cause the X server to read heap memory values and then transmit them
back to the client until encountering an unmapped page, resulting in a
crash. Despite the attacker's inability to control the specific memory
copied into the replies, the small length values typically stored in a
32-bit integer can result in significant attempted out-of-bounds reads.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31082</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31081</p>
</td>
<td rowspan="1" colspan="1">
<p>A heap-based buffer over-read vulnerability was found in the <a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">X.org</a> server's
ProcXIPassiveGrabDevice() function. This issue occurs when byte-swapped
length values are used in replies, potentially leading to memory leakage
and segmentation faults, particularly when triggered by a client with a
different endianness. This vulnerability could be exploited by an attacker
to cause the X server to read heap memory values and then transmit them
back to the client until encountering an unmapped page, resulting in a
crash. Despite the attacker's inability to control the specific memory
copied into the replies, the small length values typically stored in a
32-bit integer can result in significant attempted out-of-bounds reads.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31081</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31080</p>
</td>
<td rowspan="1" colspan="1">
<p>A heap-based buffer over-read vulnerability was found in the <a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">X.org</a> server's
ProcXIGetSelectedEvents() function. This issue occurs when byte-swapped
length values are used in replies, potentially leading to memory leakage
and segmentation faults, particularly when triggered by a client with a
different endianness. This vulnerability could be exploited by an attacker
to cause the X server to read heap memory values and then transmit them
back to the client until encountering an unmapped page, resulting in a
crash. Despite the attacker's inability to control the specific memory
copied into the replies, the small length values typically stored in a
32-bit integer can result in significant attempted out-of-bounds reads.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31080</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3226</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in Campcodes Online Patient Record Management
System 1.0. It has been classified as critical. This affects an unknown
part of the file /admin/login.php. The manipulation of the argument password
leads to sql injection. It is possible to initiate the attack remotely.
The exploit has been disclosed to the public and may be used. The associated
identifier of this vulnerability is VDB-259071.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3226</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2957</p>
</td>
<td rowspan="1" colspan="1">
<p>The Simple Ajax Chat – Add a Fast, Secure Chat Box plugin for WordPress
is vulnerable to Stored Cross-Site Scripting via the name field in all
versions up to, and including, 20240216 due to insufficient input sanitization
and output escaping. This makes it possible for unauthenticated attacker
to inject arbitrary web scripts in pages that will execute whenever a user
accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2957</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2344</p>
</td>
<td rowspan="1" colspan="1">
<p>The Avada theme for WordPress is vulnerable to SQL Injection via the 'entry'
parameter in all versions up to, and including, 7.11.6 due to insufficient
escaping on the user supplied parameter and lack of sufficient preparation
on the existing SQL query. This makes it possible for authenticted attackers,
with editor-level access and above, to append additional SQL queries into
already existing queries that can be used to extract sensitive information
from the database.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2344</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1852</p>
</td>
<td rowspan="1" colspan="1">
<p>The WP-Members Membership Plugin plugin for WordPress is vulnerable to
Stored Cross-Site Scripting via the X-Forwarded-For header in all versions
up to, and including, 3.4.9.2 due to insufficient input sanitization and
output escaping. This makes it possible for unauthenticated attackers to
inject arbitrary web scripts in pages that will execute whenever a user
accesses an injected page which is the edit users page. This vulnerability
was partially patched in version 3.4.9.2, and was fully patched in 3.4.9.3.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1852</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1812</p>
</td>
<td rowspan="1" colspan="1">
<p>The Everest Forms plugin for WordPress is vulnerable to Server-Side Request
Forgery in all versions up to, and including, 2.0.7 via the 'font_url'
parameter. This makes it possible for unauthenticated attackers to make
web requests to arbitrary locations originating from the web application
and can be used to query and modify information from internal services.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1812</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1794</p>
</td>
<td rowspan="1" colspan="1">
<p>The Forminator plugin for WordPress is vulnerable to Stored Cross-Site
Scripting via an uploaded file (e.g. 3gpp file) in all versions up to,
and including, 1.29.0 due to insufficient input sanitization and output
escaping. This makes it possible for unauthenticated attackers to inject
arbitrary web scripts in pages that will execute whenever a user accesses
an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1794</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1774</p>
</td>
<td rowspan="1" colspan="1">
<p>The Customily Product Personalizer plugin for WordPress is vulnerable
to Stored Cross-Site Scripting via user cookies in all versions up to,
and including, 1.23.3 due to insufficient input sanitization and output
escaping. This makes it possible for unauthenticated attackers to inject
arbitrary web scripts in pages that will execute whenever a user accesses
an injected page. We unfortunately could not get in touch with the vendor
through various means to disclose this issue.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1774</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-0952</p>
</td>
<td rowspan="1" colspan="1">
<p>The WP ERP | Complete HR solution with recruitment &amp; job listings
| WooCommerce CRM &amp; Accounting plugin for WordPress is vulnerable to
time-based SQL Injection via the id parameter in all versions up to, and
including, 1.12.9 due to insufficient escaping on the user supplied parameter
and lack of sufficient preparation on the existing SQL query. This makes
it possible for authenticated attackers, with accounting manager or admin
privileges or higher, to append additional SQL queries into already existing
queries that can be used to extract sensitive information from the database.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-0952</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29066</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Distributed File System (DFS) Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29066</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29055</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft Defender for IoT Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29055</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29054</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft Defender for IoT Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29054</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26233</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows DNS Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26233</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26231</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows DNS Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26231</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26227</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows DNS Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26227</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26224</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows DNS Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26224</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26223</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows DNS Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26223</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26222</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows DNS Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26222</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26221</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows DNS Server Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26221</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26208</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft Message Queuing (MSMQ) Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26208</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26202</p>
</td>
<td rowspan="1" colspan="1">
<p>DHCP Server Service Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26202</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26195</p>
</td>
<td rowspan="1" colspan="1">
<p>DHCP Server Service Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26195</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-21324</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft Defender for IoT Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-21324</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-21322</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft Defender for IoT Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-21322</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-49913</p>
</td>
<td rowspan="1" colspan="1">
<p>A stack-based buffer overflow vulnerability exists in the web interface
Radio Scheduling functionality of Tp-Link AC1350 Wireless MU-MIMO Gigabit
Access Point (EAP225 V3) v5.1.0 Build 20220926. A specially crafted series
of HTTP requests can lead to remote code execution. An attacker can make
an authenticated HTTP request to trigger this vulnerability.This vulnerability
refers specifically to the overflow that occurs via the <code>action</code> parameter
at offset <code>0x422448</code> of the <code>httpd</code> binary shipped with
v5.0.4 Build 20220216 of the EAP115.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-49913</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-49912</p>
</td>
<td rowspan="1" colspan="1">
<p>A stack-based buffer overflow vulnerability exists in the web interface
Radio Scheduling functionality of Tp-Link AC1350 Wireless MU-MIMO Gigabit
Access Point (EAP225 V3) v5.1.0 Build 20220926. A specially crafted series
of HTTP requests can lead to remote code execution. An attacker can make
an authenticated HTTP request to trigger this vulnerability.This vulnerability
refers specifically to the overflow that occurs via the <code>profile</code> parameter
at offset <code>0x4224b0</code> of the <code>httpd</code> binary shipped with
v5.0.4 Build 20220216 of the EAP115.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-49912</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-49911</p>
</td>
<td rowspan="1" colspan="1">
<p>A stack-based buffer overflow vulnerability exists in the web interface
Radio Scheduling functionality of Tp-Link AC1350 Wireless MU-MIMO Gigabit
Access Point (EAP225 V3) v5.1.0 Build 20220926. A specially crafted series
of HTTP requests can lead to remote code execution. An attacker can make
an authenticated HTTP request to trigger this vulnerability.This vulnerability
refers specifically to the overflow that occurs via the <code>band</code> parameter
at offset <code>0x422420</code> of the <code>httpd</code> binary shipped with
v5.0.4 Build 20220216 of the EAP115.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-49911</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-49910</p>
</td>
<td rowspan="1" colspan="1">
<p>A stack-based buffer overflow vulnerability exists in the web interface
Radio Scheduling functionality of Tp-Link AC1350 Wireless MU-MIMO Gigabit
Access Point (EAP225 V3) v5.1.0 Build 20220926. A specially crafted series
of HTTP requests can lead to remote code execution. An attacker can make
an authenticated HTTP request to trigger this vulnerability.This vulnerability
refers specifically to the overflow that occurs via the <code>ssid</code> parameter
at offset <code>0x42247c</code> of the <code>httpd</code> binary shipped with
v5.0.4 Build 20220216 of the EAP115.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-49910</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-49909</p>
</td>
<td rowspan="1" colspan="1">
<p>A stack-based buffer overflow vulnerability exists in the web interface
Radio Scheduling functionality of Tp-Link AC1350 Wireless MU-MIMO Gigabit
Access Point (EAP225 V3) v5.1.0 Build 20220926. A specially crafted series
of HTTP requests can lead to remote code execution. An attacker can make
an authenticated HTTP request to trigger this vulnerability.This vulnerability
refers specifically to the overflow that occurs via the <code>action</code> parameter
at offset <code>0x0045ab38</code> of the <code>httpd_portal</code> binary shipped
with v5.1.0 Build 20220926 of the EAP225.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-49909</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-49908</p>
</td>
<td rowspan="1" colspan="1">
<p>A stack-based buffer overflow vulnerability exists in the web interface
Radio Scheduling functionality of Tp-Link AC1350 Wireless MU-MIMO Gigabit
Access Point (EAP225 V3) v5.1.0 Build 20220926. A specially crafted series
of HTTP requests can lead to remote code execution. An attacker can make
an authenticated HTTP request to trigger this vulnerability.This vulnerability
refers specifically to the overflow that occurs via the <code>profile</code> parameter
at offset <code>0x0045abc8</code> of the <code>httpd_portal</code> binary shipped
with v5.1.0 Build 20220926 of the EAP225.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-49908</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-49907</p>
</td>
<td rowspan="1" colspan="1">
<p>A stack-based buffer overflow vulnerability exists in the web interface
Radio Scheduling functionality of Tp-Link AC1350 Wireless MU-MIMO Gigabit
Access Point (EAP225 V3) v5.1.0 Build 20220926. A specially crafted series
of HTTP requests can lead to remote code execution. An attacker can make
an authenticated HTTP request to trigger this vulnerability.This vulnerability
refers specifically to the overflow that occurs via the <code>band</code> parameter
at offset <code>0x0045aad8</code> of the <code>httpd_portal</code> binary shipped
with v5.1.0 Build 20220926 of the EAP225.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-49907</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-49906</p>
</td>
<td rowspan="1" colspan="1">
<p>A stack-based buffer overflow vulnerability exists in the web interface
Radio Scheduling functionality of Tp-Link AC1350 Wireless MU-MIMO Gigabit
Access Point (EAP225 V3) v5.1.0 Build 20220926. A specially crafted series
of HTTP requests can lead to remote code execution. An attacker can make
an authenticated HTTP request to trigger this vulnerability.This vulnerability
refers specifically to the overflow that occurs via the <code>ssid</code> parameter
at offset <code>0x0045ab7c</code> of the <code>httpd_portal</code> binary shipped
with v5.1.0 Build 20220926 of the EAP225.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-49906</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-6317</p>
</td>
<td rowspan="1" colspan="1">
<p>A prompt bypass exists in the secondscreen.gateway service running on
webOS version 4 through 7. An attacker can create a privileged account
without asking the user for the security PIN.&nbsp;
<br>
<br>Full versions and TV models affected:
<br>
<br>webOS 4.9.7 - 5.30.40 running on LG43UM7000PLA
<br>webOS 5.5.0 - 04.50.51 running on OLED55CXPUA
<br>webOS 6.3.3-442 (kisscurl-kinglake) - 03.36.50 running on OLED48C1PUB
&nbsp;
<br>webOS 7.3.1-43 (mullet-mebin) - 03.33.85 running on OLED55A23LA</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-6317</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27901</p>
</td>
<td rowspan="1" colspan="1">
<p>SAP Asset Accounting could allow a high privileged attacker to exploit
insufficient validation of path information provided by the users and pass
it through to the file API's. Thus, causing a considerable impact on confidentiality,
integrity and availability of the application.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27901</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31292</p>
</td>
<td rowspan="1" colspan="1">
<p>Unrestricted Upload of File with Dangerous Type vulnerability in Moove
Agency Import XML and RSS Feeds.This issue affects Import XML and RSS Feeds:
from n/a through 2.1.5.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31292</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31288</p>
</td>
<td rowspan="1" colspan="1">
<p>Server-Side Request Forgery (SSRF) vulnerability in RapidLoad RapidLoad
Power-Up for Autoptimize.This issue affects RapidLoad Power-Up for Autoptimize:
from n/a through 2.2.11.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31288</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-6522</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Privilege Management vulnerability in ExtremePacs Extreme XDS
allows Collect Data as Provided by Users.This issue affects Extreme XDS:
before 3914.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-6522</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-25695</p>
</td>
<td rowspan="1" colspan="1">
<p>There is a Cross-site Scripting vulnerability in Portal for ArcGIS in
versions &lt;= 11.2 that may allow a remote, authenticated attacker to
provide input that is not sanitized properly and is rendered in error messages.
The are no privileges required to execute this attack.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-25695</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3022</p>
</td>
<td rowspan="1" colspan="1">
<p>The BookingPress plugin for WordPress is vulnerable to arbitrary file
uploads due to insufficient filename validation in the 'bookingpress_process_upload'
function in all versions up to, and including 1.0.87. This allows an authenticated
attacker with administrator-level capabilities or higher to upload arbitrary
files on the affected site's server, enabling remote code execution.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3022</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29062</p>
</td>
<td rowspan="1" colspan="1">
<p>Secure Boot Security Feature Bypass Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29062</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-20689</p>
</td>
<td rowspan="1" colspan="1">
<p>Secure Boot Security Feature Bypass Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-20689</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-20688</p>
</td>
<td rowspan="1" colspan="1">
<p>Secure Boot Security Feature Bypass Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-20688</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31367</p>
</td>
<td rowspan="1" colspan="1">
<p>Missing Authorization vulnerability in PenciDesign Soledad.This issue
affects Soledad: from n/a through 8.4.2.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>7.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31367</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31366</p>
</td>
<td rowspan="1" colspan="1">
<p>Missing Authorization vulnerability in Themify Post Type Builder (PTB).This
issue affects Post Type Builder (PTB): from n/a through 2.0.8.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>7.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31366</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31365</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Neutralization of Input During Web Page Generation ('Cross-site
Scripting') vulnerability in Themify Post Type Builder (PTB) allows Reflected
XSS.This issue affects Post Type Builder (PTB): from n/a through 2.0.8.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>7.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31365</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31256</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Neutralization of Input During Web Page Generation ('Cross-site
Scripting') vulnerability in WebinarPress allows Reflected XSS.This issue
affects WebinarPress: from n/a through 1.33.9.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>7.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31256</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31255</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Neutralization of Input During Web Page Generation ('Cross-site
Scripting') vulnerability in ELEXtensions ELEX WooCommerce Dynamic Pricing
and Discounts allows Reflected XSS.This issue affects ELEX WooCommerce
Dynamic Pricing and Discounts: from n/a through 2.1.2.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>7.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31255</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1385</p>
</td>
<td rowspan="1" colspan="1">
<p>The WP-Stateless – Google Cloud Storage plugin for WordPress is vulnerable
to unauthorized loss of data due to a missing capability check on the dismiss_notices()
function in all versions up to, and including, 3.4.0. This makes it possible
for authenticated attackers, with subscriber-level access and above, to
update arbitrary option values to the current time, which may completely
take a site offline.</p>
</td>
<td rowspan="1" colspan="1">
<p>7.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1385</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-25007</p>
</td>
<td rowspan="1" colspan="1">
<p>
<br>Ericsson Network Manager (ENM), versions prior to 23.1, contains a vulnerability
in the export function of application log where Improper Neutralization
of Formula Elements in a CSV File can lead to code execution or information
disclosure. There is limited impact to integrity and availability. The
attacker on the adjacent network with administration access can exploit
the vulnerability.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>7.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-25007</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-25115</p>
</td>
<td rowspan="1" colspan="1">
<p>RedisBloom adds a set of probabilistic data structures to Redis. Starting
in version 2.0.0 and prior to version 2.4.7 and 2.6.10, specially crafted <code>CF.LOADCHUNK</code> commands
may be used by authenticated users to perform heap overflow, which may
lead to remote code execution. The problem is fixed in RedisBloom 2.4.7
and 2.6.10.</p>
</td>
<td rowspan="1" colspan="1">
<p>7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-25115</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26243</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows USB Print Driver Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26243</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26242</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Telephony Server Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26242</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26236</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Update Stack Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26236</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26213</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft Brokering File System Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26213</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2700</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in the quarkus-core component. Quarkus captures
the local environment variables from the Quarkus namespace during the application's
build. Thus, running the resulting application inherits the values captured
at build time. \r
<br>\r
<br>However, some local environment variables may have been set by the developer
/ CI environment for testing purposes, such as dropping the database during
the application startup or trusting all TLS certificates to accept self-signed
certificates. If these properties are configured using environment variables
or the .env facility, they are captured into the built application. It
leads to dangerous behavior if the application does not override these
values.\r
<br>\r
<br>This behavior only happens for configuration properties from the <code>quarkus.*</code> namespace.
So, application-specific properties are not captured.</p>
</td>
<td rowspan="1" colspan="1">
<p>7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2700</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2654</p>
</td>
<td rowspan="1" colspan="1">
<p>The File Manager plugin for WordPress is vulnerable to Directory Traversal
in all versions up to, and including, 7.2.5 via the fm_download_backup
function. This makes it possible for authenticated attackers, with administrator
access and above, to read the contents of arbitrary zip files on the server,
which can contain sensitive information.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2654</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28897</p>
</td>
<td rowspan="1" colspan="1">
<p>Secure Boot Security Feature Bypass Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>6.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28897</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26253</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows rndismp6.sys Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>6.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26253</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26252</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows rndismp6.sys Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>6.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26252</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26251</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft SharePoint Server Spoofing Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>6.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26251</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26168</p>
</td>
<td rowspan="1" colspan="1">
<p>Secure Boot Security Feature Bypass Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>6.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26168</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-38729</p>
</td>
<td rowspan="1" colspan="1">
<p>IBM Db2 for Linux, UNIX and Windows (includes Db2 Connect Server)10.5,
11.1, and 11.5 is vulnerable to sensitive information disclosure when using
ADMIN_CMD with IMPORT or EXPORT. IBM X-Force ID: 262259.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-38729</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28924</p>
</td>
<td rowspan="1" colspan="1">
<p>Secure Boot Security Feature Bypass Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>6.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28924</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28921</p>
</td>
<td rowspan="1" colspan="1">
<p>Secure Boot Security Feature Bypass Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>6.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28921</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28919</p>
</td>
<td rowspan="1" colspan="1">
<p>Secure Boot Security Feature Bypass Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>6.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28919</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28903</p>
</td>
<td rowspan="1" colspan="1">
<p>Secure Boot Security Feature Bypass Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>6.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28903</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26250</p>
</td>
<td rowspan="1" colspan="1">
<p>Secure Boot Security Feature Bypass Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>6.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26250</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26234</p>
</td>
<td rowspan="1" colspan="1">
<p>Proxy Driver Spoofing Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>6.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26234</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26171</p>
</td>
<td rowspan="1" colspan="1">
<p>Secure Boot Security Feature Bypass Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>6.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26171</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-20669</p>
</td>
<td rowspan="1" colspan="1">
<p>Secure Boot Security Feature Bypass Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>6.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-20669</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-48784</p>
</td>
<td rowspan="1" colspan="1">
<p>A&nbsp;use of externally-controlled format string vulnerability [CWE-134]
in FortiOS version 7.4.1 and below, version 7.2.7 and below, version 7.0.14
and below, version 6.4.15 and below command line interface may allow a
local&nbsp;privileged attacker with super-admin profile and CLI access&nbsp;to
execute arbitrary code or commands via specially crafted requests.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-48784</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-47542</p>
</td>
<td rowspan="1" colspan="1">
<p>A improper neutralization of special elements used in a template engine
[CWE-1336] in FortiManager versions 7.4.1 and below, versions 7.2.4 and
below, and 7.0.10 and below allows attacker to execute unauthorized code
or commands via specially crafted templates.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-47542</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-47541</p>
</td>
<td rowspan="1" colspan="1">
<p>An improper limitation of a pathname to a restricted directory ('path
traversal') in Fortinet FortiSandbox version 4.4.0 through 4.4.2 and 4.2.0
through 4.2.6 and 4.0.0 through 4.0.5 and 3.2.0 through 3.2.4 and 3.1.0
through 3.1.5 and 3.0.0 through 3.0.7 and 2.5.0 through 2.5.2 and 2.4.0
through 2.4.1 and 2.3.0 through 2.3.3 and 2.2.0 through 2.2.2 and 2.1.0
through 2.1.3 and 2.0.0 through 2.0.3 allows attacker to execute unauthorized
code or commands via CLI.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-47541</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-47540</p>
</td>
<td rowspan="1" colspan="1">
<p>An improper neutralization of special elements used in an os command ('os
command injection') in Fortinet FortiSandbox version 4.4.0 through 4.4.2
and 4.2.0 through 4.2.6 and 4.0.0 through 4.0.5 and 3.2.0 through 3.2.4
and 3.0.5 through 3.0.7 may allows attacker to execute unauthorized code
or commands via CLI.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-47540</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-5912</p>
</td>
<td rowspan="1" colspan="1">
<p>
<br>A potential memory leakage vulnerability was reported in some Lenovo Notebook
products that may allow a local attacker with elevated privileges to write
to NVRAM variables.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>6.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-5912</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-25494</p>
</td>
<td rowspan="1" colspan="1">
<p>
<br>A potential vulnerability were reported in the BIOS of some Desktop, Smart
Edge, and ThinkStation products that could allow a local attacker with
elevated privileges to write to NVRAM variables.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>6.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-25494</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-25493</p>
</td>
<td rowspan="1" colspan="1">
<p>
<br>A potential vulnerability was reported in the BIOS update tool driver
for some Desktop, Smart Edge, Smart Office, and ThinkStation products that
could allow a local user with elevated privileges to execute arbitrary
code.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>6.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-25493</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2312</p>
</td>
<td rowspan="1" colspan="1">
<p>GRUB2 does not call the module fini functions on exit, leading to Debian/Ubuntu's
peimage GRUB2 module leaving UEFI system table hooks after exit. This lead
to a use-after-free condition, and could possibly lead to secure boot bypass.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2312</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31212</p>
</td>
<td rowspan="1" colspan="1">
<p>InstantCMS is a free and open source content management system. A SQL
injection vulnerability affects instantcms v2.16.2 in which an attacker
with administrative privileges can cause the application to execute unauthorized
SQL code. The vulnerability exists in index_chart_data action, which receives
an input from user and passes it unsanitized to the core model <code>filterFunc</code> function
that further embeds this data in an SQL statement. This allows attackers
to inject unwanted SQL code into the statement. The <code>period</code> should
be escaped before inserting it in the query. As of time of publication,
a patched version is not available.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31212</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28219</p>
</td>
<td rowspan="1" colspan="1">
<p>In _imagingcms.c in Pillow before 10.3.0, a buffer overflow exists because
strcpy is used instead of strncpy.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28219</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-23584</p>
</td>
<td rowspan="1" colspan="1">
<p>The NMAP Importer service? may expose data store credentials to authorized
users of the Windows Registry.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.6</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-23584</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2792</p>
</td>
<td rowspan="1" colspan="1">
<p>The Elementor Addon Elements plugin for WordPress is vulnerable to Stored
Cross-Site Scripting via widgets in all versions up to, and including,
1.13.2 due to insufficient input sanitization and output escaping on user
supplied attributes. This makes it possible for authenticated attackers,
with contributor-level access and above, to inject arbitrary web scripts
in pages that will execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2792</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2093</p>
</td>
<td rowspan="1" colspan="1">
<p>The VK All in One Expansion Unit plugin for WordPress is vulnerable to
Sensitive Information Exposure in all versions up to, and including, 9.95.0.1
via social meta tags. This makes it possible for unauthenticated attackers
to view limited password protected content.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2093</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1352</p>
</td>
<td rowspan="1" colspan="1">
<p>The Classified Listing – Classified ads &amp; Business Directory Plugin
plugin for WordPress is vulnerable to unauthorized access &amp; modification
of data due to a missing capability check on the rtcl_import_location()
rtcl_import_category() functions in all versions up to, and including,
3.0.4. This makes it possible for authenticated attackers, with subscriber-level
access and above, to create terms.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1352</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1289</p>
</td>
<td rowspan="1" colspan="1">
<p>The LearnPress – WordPress LMS Plugin plugin for WordPress is vulnerable
to Insecure Direct Object Reference in all versions up to, and including,
4.2.6.3 due to missing validation on a user controlled key when looking
up order information. This makes it possible for authenticated attackers
to obtain information on orders placed by other users and guests, which
can be leveraged to sign up for paid courses that were purchased by guests.
Emails of other users are also exposed.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1289</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-6695</p>
</td>
<td rowspan="1" colspan="1">
<p>The Beaver Themer plugin for WordPress is vulnerable to Sensitive Information
Exposure in all versions up to, and including, 1.4.9 via the 'wpbb' shortcode.
This makes it possible for authenticated attackers, with contributor access
and above, to extract sensitive data including arbitrary user_meta values.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-6695</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31454</p>
</td>
<td rowspan="1" colspan="1">
<p>PsiTransfer is an open source, self-hosted file sharing solution. Prior
to version 2.2.0, the absence of restrictions on the endpoint, which is
designed for uploading files, allows an attacker who received the id of
a file distribution to change the files that are in this distribution.
The vulnerability allows an attacker to influence those users who come
to the file distribution after them and slip the victim files with a malicious
or phishing signature. Version 2.2.0 contains a patch for this issue.
<br>
<br>CVE-2024-31454 allows users to violate the integrity of a file that is
uploaded by another user. In this case, additional files are not loaded
into the file bucket. Violation of integrity at the level of individual
files. While the vulnerability with the number CVE-2024-31453 allows users
to violate the integrity of a file bucket without violating the integrity
of files uploaded by other users. Thus, vulnerabilities are reproduced
differently, require different security recommendations and affect different
objects of the application’s business logic.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31454</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31453</p>
</td>
<td rowspan="1" colspan="1">
<p>PsiTransfer is an open source, self-hosted file sharing solution. Prior
to version 2.2.0, the absence of restrictions on the endpoint, which allows
users to create a path for uploading a file in a file distribution, allows
an attacker to add arbitrary files to the distribution. The vulnerability
allows an attacker to influence those users who come to the file distribution
after them and slip the victim files with a malicious or phishing signature.
Version 2.2.0 contains a patch for the issue.
<br>
<br>CVE-2024-31453 allows users to violate the integrity of a file bucket
and upload new files there, while the vulnerability with the number CVE-2024-31454
allows users to violate the integrity of a single file that is uploaded
by another user by writing data there and not allows you to upload new
files to the bucket. Thus, vulnerabilities are reproduced differently,
require different security recommendations and affect different objects
of the application’s business logic.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31453</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26226</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Distributed File System (DFS) Information Disclosure Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26226</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26183</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Kerberos Denial of Service Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26183</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-21424</p>
</td>
<td rowspan="1" colspan="1">
<p>Azure Compute Gallery Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-21424</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31368</p>
</td>
<td rowspan="1" colspan="1">
<p>Missing Authorization vulnerability in PenciDesign Soledad.This issue
affects Soledad: from n/a through 8.4.2.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31368</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30218</p>
</td>
<td rowspan="1" colspan="1">
<p>The ABAP Application Server of SAP NetWeaver as well as ABAP Platform&nbsp;allows
an attacker to prevent legitimate users from accessing a service, either
by crashing or flooding the service. This leads to a considerable impact
on availability.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30218</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28167</p>
</td>
<td rowspan="1" colspan="1">
<p>SAP Group Reporting Data Collection&nbsp;does not perform necessary authorization
checks for an authenticated user, resulting in escalation of privileges.
On successful exploitation, specific data can be changed via the Enter
Package Data app although the user does not have sufficient authorization
causing high impact on Integrity of the appliction.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28167</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-0083</p>
</td>
<td rowspan="1" colspan="1">
<p>NVIDIA ChatRTX for Windows contains a vulnerability in the UI, where an
attacker can cause a cross-site scripting error by network by running malicious
scripts in users' browsers. A successful exploit of this vulnerability
might lead to code execution, denial of service, and information disclosure.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-0083</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31357</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Neutralization of Input During Web Page Generation ('Cross-site
Scripting') vulnerability in BdThemes Ultimate Store Kit Elementor Addons
allows Stored XSS.This issue affects Ultimate Store Kit Elementor Addons:
from n/a through 1.5.2.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31357</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31349</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Neutralization of Input During Web Page Generation ('Cross-site
Scripting') vulnerability in MailMunch MailMunch – Grow your Email List
allows Stored XSS.This issue affects MailMunch – Grow your Email List:
from n/a through 3.1.6.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31349</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31348</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Neutralization of Input During Web Page Generation ('Cross-site
Scripting') vulnerability in Themepoints Testimonials allows Stored XSS.This
issue affects Testimonials: from n/a through 3.0.5.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31348</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31346</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Neutralization of Input During Web Page Generation ('Cross-site
Scripting') vulnerability in Blocksmarket Gradient Text Widget for Elementor
allows Stored XSS.This issue affects Gradient Text Widget for Elementor:
from n/a through 1.0.1.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31346</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31306</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Neutralization of Input During Web Page Generation ('Cross-site
Scripting') vulnerability in WPDeveloper Essential Blocks for Gutenberg
allows Stored XSS.This issue affects Essential Blocks for Gutenberg: from
n/a through 4.5.3.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31306</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31258</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Neutralization of Input During Web Page Generation ('Cross-site
Scripting') vulnerability in <a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">Micro.Company</a> Form to Chat App allows Stored
XSS.This issue affects Form to Chat App: from n/a through 1.1.6.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31258</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31257</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Neutralization of Input During Web Page Generation ('Cross-site
Scripting') vulnerability in Formsite Formsite | Embed online forms to
collect orders, registrations, leads, and surveys allows Stored XSS.This
issue affects Formsite | Embed online forms to collect orders, registrations,
leads, and surveys: from n/a through 1.6.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31257</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31236</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Neutralization of Input During Web Page Generation ('Cross-site
Scripting') vulnerability in WP Royal Royal Elementor Addons allows Stored
XSS.This issue affects Royal Elementor Addons: from n/a through 1.3.93.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31236</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-4605</p>
</td>
<td rowspan="1" colspan="1">
<p>
<br>A valid authenticated Lenovo XClarity Administrator (LXCA) user can potentially
leverage an unauthenticated API endpoint to retrieve system event information.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-4605</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2447</p>
</td>
<td rowspan="1" colspan="1">
<p>Mattermost versions 8.1.x before 8.1.11, 9.3.x before 9.3.3, 9.4.x before
9.4.4, and 9.5.x before 9.5.2 fail to authenticate the source of certain
types of post actions, allowing an authenticated attacker to create posts
as other users via a crafted post action.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2447</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2103</p>
</td>
<td rowspan="1" colspan="1">
<p>
<br>Inclusion of undocumented features vulnerability accessible when logged
on with a privileged access level on the following Schweitzer Engineering
Laboratories relays could allow the relay to behave unpredictably:
<br>SEL-700BT Motor Bus Transfer Relay, SEL-700G Generator Protection Relay,
SEL-710-5 Motor Protection Relay, SEL-751 Feeder Protection Relay, SEL-787-2/-3/-4
Transformer Protection Relay, SEL-787Z High-Impedance Differential Relay
<br>
<br>. See product instruction manual appendix A dated 20240308 for more details
regarding the SEL-751 Feeder Protection Relay. For more information for
the other affected products, see their instruction manuals dated 20240329.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2103</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3250</p>
</td>
<td rowspan="1" colspan="1">
<p>It was discovered that Canonical's Pebble service manager read-file API
and the associated pebble pull command, before v1.10.2, allowed unprivileged
local users to read files with root-equivalent permissions when Pebble
was running as root. Fixes are also available as backports to v1.1.1, v1.4.2,
and v1.7.4.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3250</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-20368</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability in the web-based management interface of Cisco Identity
Services Engine (ISE) could allow an unauthenticated, remote attacker to
conduct a cross-site request forgery (CSRF) attack and perform arbitrary
actions on an affected device.\r
<br>\r This vulnerability is due to insufficient CSRF protections for the
web-based management interface of an affected device. An attacker could
exploit this vulnerability by persuading a user of the interface to follow
a crafted link. A successful exploit could allow the attacker to perform
arbitrary actions on the affected device with the privileges of the targeted
user.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-20368</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31420</p>
</td>
<td rowspan="1" colspan="1">
<p>A NULL pointer dereference flaw was found in KubeVirt. This flaw allows
an attacker who has access to a virtual machine guest on a node with DownwardMetrics
enabled to cause a denial of service by issuing a high number of calls
to vm-dump-metrics --virtio and then deleting the virtual machine.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31420</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3514</p>
</td>
<td rowspan="1" colspan="1">
<p>The Responsive Tabs plugin for WordPress is vulnerable to Stored Cross-Site
Scripting via the tabs_color value in all versions up to, and including,
4.0.6 due to insufficient input sanitization and output escaping on user
supplied attributes. This makes it possible for authenticated attackers,
with contributor-level access and above, to inject arbitrary web scripts
in pages that will execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3514</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3512</p>
</td>
<td rowspan="1" colspan="1">
<p>The WP Shortcodes Plugin — Shortcodes Ultimate plugin for WordPress is
vulnerable to Stored Cross-Site Scripting via the plugin's 'note_color'
shortcode in all versions up to, and including, 7.0.4 due to insufficient
input sanitization and output escaping on user supplied attributes. This
makes it possible for authenticated attackers, with contributor-level access
and above, to inject arbitrary web scripts in pages that will execute whenever
a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3512</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3267</p>
</td>
<td rowspan="1" colspan="1">
<p>The Bold Page Builder plugin for WordPress is vulnerable to Stored Cross-Site
Scripting via the plugin's bt_bb_price_list shortcode in all versions up
to, and including, 4.8.8 due to insufficient input sanitization and output
escaping on user supplied attributes. This makes it possible for authenticated
attackers, with contributor-level access and above, to inject arbitrary
web scripts in pages that will execute whenever a user accesses an injected
page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3267</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3266</p>
</td>
<td rowspan="1" colspan="1">
<p>The Bold Page Builder plugin for WordPress is vulnerable to Stored Cross-Site
Scripting via the URL attribute of widgets in all versions up to, and including,
4.8.8 due to insufficient input sanitization and output escaping on user
supplied attributes. This makes it possible for authenticated attackers,
with contributor-level access and above, to inject arbitrary web scripts
in pages that will execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3266</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3244</p>
</td>
<td rowspan="1" colspan="1">
<p>The EmbedPress – Embed PDF, Google Docs, Vimeo, Wistia, Embed YouTube
Videos, Audios, Maps &amp; Embed Any Documents in Gutenberg &amp; Elementor
plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the
plugin's \r
<br>'embedpress_calendar' shortcode in all versions up to, and including,
3.9.14 due to insufficient input sanitization and output escaping on user
supplied attributes. This makes it possible for authenticated attackers,
with contributor-level access and above, to inject arbitrary web scripts
in pages that will execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3244</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3208</p>
</td>
<td rowspan="1" colspan="1">
<p>The Sydney Toolbox plugin for WordPress is vulnerable to Stored Cross-Site
Scripting via the plugin's Filterable Gallery widget in all versions up
to, and including, 1.28 due to insufficient input sanitization and output
escaping on user supplied attributes. This makes it possible for authenticated
attackers, with contributor-level access and above, to inject arbitrary
web scripts in pages that will execute whenever a user accesses an injected
page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3208</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3167</p>
</td>
<td rowspan="1" colspan="1">
<p>The Ocean Extra plugin for WordPress is vulnerable to Stored Cross-Site
Scripting via the ‘twitter_username’ parameter in versions up to, and including,
2.2.6 due to insufficient input sanitization and output escaping. This
makes it possible for authenticated attackers, with contributor-level permissions
and above, to inject arbitrary web scripts in pages that will execute whenever
a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3167</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3064</p>
</td>
<td rowspan="1" colspan="1">
<p>The Elementor Addons, Widgets and Enhancements – Stax plugin for WordPress
is vulnerable to Stored Cross-Site Scripting via the plugin's 'Heading'
widgets in all versions up to, and including, 1.4.4.1 due to insufficient
input sanitization and output escaping on user supplied attributes. This
makes it possible for authenticated attackers, with contributor-level access
and above, to inject arbitrary web scripts in pages that will execute whenever
a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3064</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3053</p>
</td>
<td rowspan="1" colspan="1">
<p>The Forminator – Contact Form, Payment Form &amp; Custom Form Builder
plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the
‘id’ forminator_form shortcode attribute in versions up to, and including,
1.29.2 due to insufficient input sanitization and output escaping. This
makes it possible for authenticated attackers, with contributor-level permissions
and above, to inject arbitrary web scripts in pages that will execute whenever
a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3053</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2946</p>
</td>
<td rowspan="1" colspan="1">
<p>The ShopLentor – WooCommerce Builder for Elementor &amp; Gutenberg +12
Modules – All in One Solution (formerly WooLentor) plugin for WordPress
is vulnerable to Stored Cross-Site Scripting via the plugin's QR Code Widget
in all versions up to, and including, 2.8.4 due to insufficient input sanitization
and output escaping on user supplied attributes. This makes it possible
for authenticated attackers, with contributor-level access and above, to
inject arbitrary web scripts in pages that will execute whenever a user
accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2946</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2871</p>
</td>
<td rowspan="1" colspan="1">
<p>The Media Library Assistant plugin for WordPress is vulnerable to SQL
Injection via the plugin's shortcode(s) in all versions up to, and including,
3.13 due to insufficient escaping on the user supplied parameter and lack
of sufficient preparation on the existing SQL query. This makes it possible
for authenticated attackers, with contributor access or higher, to append
additional SQL queries into already existing queries that can be used to
extract sensitive information from the database.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2871</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2866</p>
</td>
<td rowspan="1" colspan="1">
<p>The Gutenberg Blocks by Kadence Blocks – Page Builder Features plugin
for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's
Advanced Form widget in all versions up to, and including, 3.2.25 due to
insufficient input sanitization and output escaping on user supplied attributes
such as 'placeholder'. This makes it possible for authenticated attackers,
with contributor-level access and above, to inject arbitrary web scripts
in pages that will execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2866</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2847</p>
</td>
<td rowspan="1" colspan="1">
<p>The WordPress File Upload plugin for WordPress is vulnerable to Stored
Cross-Site Scripting via the plugin's shortcode(s) in all versions up to,
and including, 4.24.5 due to insufficient input sanitization and output
escaping on user supplied attributes. This makes it possible for authenticated
attackers, with contributor-level access and above, to inject arbitrary
web scripts in pages that will execute whenever a user accesses an injected
page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2847</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2845</p>
</td>
<td rowspan="1" colspan="1">
<p>The BetterDocs – Best Documentation, FAQ &amp; Knowledge Base Plugin with
AI Support &amp; Instant Answer For Elementor &amp; Gutenberg plugin for
WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's
shortcode(s) in all versions up to, and including, 3.4.2 due to insufficient
input sanitization and output escaping on user supplied attributes. This
makes it possible for authenticated attackers, with contributor-level access
and above, to inject arbitrary web scripts in pages that will execute whenever
a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2845</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2789</p>
</td>
<td rowspan="1" colspan="1">
<p>The Happy Addons for Elementor plugin for WordPress is vulnerable to Stored
Cross-Site Scripting via the plugin's Calendy widget in all versions up
to, and including, 3.10.4 due to insufficient input sanitization and output
escaping on user supplied attributes. This makes it possible for authenticated
attackers, with contributor-level access and above, to inject arbitrary
web scripts in pages that will execute whenever a user accesses an injected
page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2789</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2788</p>
</td>
<td rowspan="1" colspan="1">
<p>The Happy Addons for Elementor plugin for WordPress is vulnerable to Stored
Cross-Site Scripting via the Post Title HTML Tag in all versions up to,
and including, 3.10.4 due to insufficient input sanitization and output
escaping on user supplied attributes. This makes it possible for authenticated
attackers, with contributor-level access and above, to inject arbitrary
web scripts in pages that will execute whenever a user accesses an injected
page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2788</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2787</p>
</td>
<td rowspan="1" colspan="1">
<p>The Happy Addons for Elementor plugin for WordPress is vulnerable to Stored
Cross-Site Scripting via the Page Title HTML Tag in all versions up to,
and including, 3.10.4 due to insufficient input sanitization and output
escaping on user supplied attributes. This makes it possible for authenticated
attackers, with contributor-level access and above, to inject arbitrary
web scripts in pages that will execute whenever a user accesses an injected
page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2787</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2783</p>
</td>
<td rowspan="1" colspan="1">
<p>The GamiPress – The #1 gamification plugin to reward points, achievements,
badges &amp; ranks in WordPress plugin for WordPress is vulnerable to Stored
Cross-Site Scripting via the plugin's shortcode(s) in all versions up to,
and including, 6.9.0 due to insufficient input sanitization and output
escaping on user supplied attributes. This makes it possible for authenticated
attackers, with contributor-level access and above, to inject arbitrary
web scripts in pages that will execute whenever a user accesses an injected
page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2783</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2650</p>
</td>
<td rowspan="1" colspan="1">
<p>The Essential Addons for Elementor – Best Elementor Templates, Widgets,
Kits &amp; WooCommerce Builders plugin for WordPress is vulnerable to Stored
Cross-Site Scripting via the alignment parameter in the Woo Product Carousel
widget in all versions up to, and including, 5.9.10 due to insufficient
input sanitization and output escaping. This makes it possible for authenticated
attackers, with contributor access or higher, to inject arbitrary web scripts
in pages that will execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2650</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2623</p>
</td>
<td rowspan="1" colspan="1">
<p>The Essential Addons for Elementor – Best Elementor Templates, Widgets,
Kits &amp; WooCommerce Builders plugin for WordPress is vulnerable to Stored
Cross-Site Scripting via the countdown widget's message parameter in all
versions up to, and including, 5.9.11 due to insufficient input sanitization
and output escaping. This makes it possible for authenticated attackers,
with contributor access or higher, to inject arbitrary web scripts in pages
that will execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2623</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2536</p>
</td>
<td rowspan="1" colspan="1">
<p>The Rank Math SEO with AI SEO Tools plugin for WordPress is vulnerable
to Stored Cross-Site Scripting via the HowTo block attributes in all versions
up to, and including, 1.0.214 due to insufficient input sanitization and
output escaping on user supplied attributes. This makes it possible for
authenticated attackers, with contributor-level access and above, to inject
arbitrary web scripts in pages that will execute whenever a user accesses
an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2536</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2513</p>
</td>
<td rowspan="1" colspan="1">
<p>The WP Chat App plugin for WordPress is vulnerable to Stored Cross-Site
Scripting via the 'imageAlt' block attribute in all versions up to, and
including, 3.6.2 due to insufficient input sanitization and output escaping
on user supplied attributes. This makes it possible for authenticated attackers,
with contributor-level access and above, to inject arbitrary web scripts
in pages that will execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2513</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2507</p>
</td>
<td rowspan="1" colspan="1">
<p>The JetWidgets For Elementor plugin for WordPress is vulnerable to Stored
Cross-Site Scripting via the widget button URL in all versions up to, and
including, 1.0.16 due to insufficient input sanitization and output escaping
on user supplied attributes. This makes it possible for authenticated attackers,
with contributor-level access and above, to inject arbitrary web scripts
in pages that will execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2507</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2504</p>
</td>
<td rowspan="1" colspan="1">
<p>The Page Builder: Pagelayer – Drag and Drop website builder plugin for
WordPress is vulnerable to Stored Cross-Site Scripting via the 'attr' parameter
in all versions up to, and including, 1.8.4 due to insufficient input sanitization
and output escaping on user supplied attributes. This makes it possible
for authenticated attackers, with contributor-level access and above, to
inject arbitrary web scripts in pages that will execute whenever a user
accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2504</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2492</p>
</td>
<td rowspan="1" colspan="1">
<p>The PowerPack Addons for Elementor plugin for WordPress is vulnerable
to Stored Cross-Site Scripting via the Twitter Tweet widget in all versions
up to, and including, 2.7.18 due to insufficient input sanitization and
output escaping. This makes it possible for authenticated attackers, with
contributor-level access and above, to inject arbitrary web scripts in
pages that will execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2492</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2457</p>
</td>
<td rowspan="1" colspan="1">
<p>The Modal Window – create popup modal window plugin for WordPress is vulnerable
to Stored Cross-Site Scripting via the plugin's shortcode(s) in all versions
up to, and including, 5.3.8 due to insufficient input sanitization and
output escaping on user supplied attributes. This makes it possible for
authenticated attackers with contributor-level and above permissions to
inject arbitrary web scripts in pages that will execute whenever a user
accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2457</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2456</p>
</td>
<td rowspan="1" colspan="1">
<p>The Ecwid Ecommerce Shopping Cart plugin for WordPress is vulnerable to
Stored Cross-Site Scripting via the plugin's shortcode(s) in all versions
up to, and including, 6.12.10 due to insufficient input sanitization and
output escaping on user supplied attributes. This makes it possible for
authenticated attackers with contributor-level and above permissions to
inject arbitrary web scripts in pages that will execute whenever a user
accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2456</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2436</p>
</td>
<td rowspan="1" colspan="1">
<p>The Lightweight Accordion plugin for WordPress is vulnerable to Stored
Cross-Site Scripting via the plugin's shortcode(s) in all versions up to,
and including, 1.5.16 due to insufficient input sanitization and output
escaping on user supplied attributes. This makes it possible for authenticated
attackers with contributor-level and above permissions to inject arbitrary
web scripts in pages that will execute whenever a user accesses an injected
page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2436</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2423</p>
</td>
<td rowspan="1" colspan="1">
<p>The UsersWP – Front-end login form, User Registration, User Profile &amp;
Members Directory plugin for WordPress plugin for WordPress is vulnerable
to Stored Cross-Site Scripting via the plugin's shortcode(s) in all versions
up to, and including, 1.2.6 due to insufficient input sanitization and
output escaping on user supplied attributes. This makes it possible for
authenticated attackers with contributor-level and above permissions to
inject arbitrary web scripts in pages that will execute whenever a user
accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2423</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2348</p>
</td>
<td rowspan="1" colspan="1">
<p>The Gum Elementor Addon plugin for WordPress is vulnerable to Stored Cross-Site
Scripting via the Post Meta widget in all versions up to, and including,
1.3.2 due to insufficient input sanitization and output escaping. This
makes it possible for authenticated attackers, with subscriber-level access
and above, to inject arbitrary web scripts in pages that will execute whenever
a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2348</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2347</p>
</td>
<td rowspan="1" colspan="1">
<p>The Astra theme for WordPress is vulnerable to Stored Cross-Site Scripting
via a user's display name in all versions up to, and including, 4.6.8 due
to insufficient input sanitization and output escaping. This makes it possible
for authenticated attackers, with contributor-level access and above, to
inject arbitrary web scripts in pages that will execute whenever a user
accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2347</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2343</p>
</td>
<td rowspan="1" colspan="1">
<p>The Avada | Website Builder For WordPress &amp; WooCommerce theme for
WordPress is vulnerable to Server-Side Request Forgery in all versions
up to, and including, 7.11.6 via the form_to_url_action function. This
makes it possible for authenticated attackers, with contributor-level access
and above, to make web requests to arbitrary locations originating from
the web application and can be used to query and modify information from
internal services.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2343</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2336</p>
</td>
<td rowspan="1" colspan="1">
<p>The Popup Maker – Popup for opt-ins, lead gen, &amp; more plugin for WordPress
is vulnerable to Stored Cross-Site Scripting via the plugin's shortcode(s)
in all versions up to, and including, 1.18.2 due to insufficient input
sanitization and output escaping on user supplied attributes. This makes
it possible for authenticated attackers with contributor-level and above
permissions to inject arbitrary web scripts in pages that will execute
whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2336</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2335</p>
</td>
<td rowspan="1" colspan="1">
<p>The Elements Plus! plugin for WordPress is vulnerable to Stored Cross-Site
Scripting via multiple widget link URLs in all versions up to, and including,
2.16.2 due to insufficient input sanitization and output escaping on user
supplied attributes. This makes it possible for authenticated attackers
with contributor-level and above permissions to inject arbitrary web scripts
in pages that will execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2335</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2334</p>
</td>
<td rowspan="1" colspan="1">
<p>The Template Kit – Import plugin for WordPress is vulnerable to Stored
Cross-Site Scripting via the template upload functionality in all versions
up to, and including, 1.0.14 due to insufficient input sanitization and
output escaping. This makes it possible for authenticated attackers, with
author access and above, to inject arbitrary web scripts in pages that
will execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2334</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2327</p>
</td>
<td rowspan="1" colspan="1">
<p>The Global Elementor Buttons plugin for WordPress is vulnerable to Stored
Cross-Site Scripting via the button link URL in all versions up to, and
including, 1.1.0 due to insufficient input sanitization and output escaping
on user supplied attributes. This makes it possible for authenticated attackers
with contributor-level and above permissions to inject arbitrary web scripts
in pages that will execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2327</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2311</p>
</td>
<td rowspan="1" colspan="1">
<p>The Avada theme for WordPress is vulnerable to Stored Cross-Site Scripting
via the plugin's shortcodes in all versions up to, and including, 7.11.6
due to insufficient input sanitization and output escaping on user supplied
attributes. This makes it possible for authenticated attackers with contributor-level
and above permissions to inject arbitrary web scripts in pages that will
execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2311</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2306</p>
</td>
<td rowspan="1" colspan="1">
<p>The Revslider plugin for WordPress is vulnerable to Stored Cross-Site
Scripting via svg upload in all versions up to, and including, 6.6.20 due
to insufficient input sanitization and output escaping. This makes it possible
for authenticated attackers to inject arbitrary web scripts in pages that
will execute whenever a user accesses an injected page. By default, this
can only be exploited by administrators, but the ability to use and configure
revslider can be extended to authors.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2306</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2305</p>
</td>
<td rowspan="1" colspan="1">
<p>The Cards for Beaver Builder plugin for WordPress is vulnerable to Stored
Cross-Site Scripting via the BootstrapCard link in all versions up to,
and including, 1.1.2 due to insufficient input sanitization and output
escaping on user supplied attributes. This makes it possible for authenticated
attackers with contributor-level and above permissions to inject arbitrary
web scripts in pages that will execute whenever a user accesses an injected
page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2305</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2289</p>
</td>
<td rowspan="1" colspan="1">
<p>The PowerPack Lite for Beaver Builder plugin for WordPress is vulnerable
to Stored Cross-Site Scripting via the link in multiple elements in all
versions up to, and including, 1.3.0 due to insufficient input sanitization
and output escaping on user supplied attributes. This makes it possible
for authenticated attackers with contributor-level and above permissions
to inject arbitrary web scripts in pages that will execute whenever a user
accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2289</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2287</p>
</td>
<td rowspan="1" colspan="1">
<p>The Knight Lab Timeline plugin for WordPress is vulnerable to Stored Cross-Site
Scripting via the plugin's shortcode(s) in all versions up to, and including,
3.9.3.3 due to insufficient input sanitization and output escaping on user
supplied attributes. This makes it possible for authenticated attackers
with contributor-level and above permissions to inject arbitrary web scripts
in pages that will execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2287</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2226</p>
</td>
<td rowspan="1" colspan="1">
<p>The Otter Blocks – Gutenberg Blocks, Page Builder for Gutenberg Editor
&amp; FSE plugin for WordPress is vulnerable to Stored Cross-Site Scripting
via the id parameter in the google-map block in all versions up to, and
including, 2.6.4 due to insufficient input sanitization and output escaping.
This makes it possible for authenticated attackers with contributor access
and higher to inject arbitrary web scripts in pages that will execute whenever
a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2226</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2187</p>
</td>
<td rowspan="1" colspan="1">
<p>The Beaver Builder Addons by WPZOOM plugin for WordPress is vulnerable
to Stored Cross-Site Scripting via the Testimonials widget in all versions
up to, and including, 1.3.4 due to insufficient input sanitization and
output escaping. This makes it possible for authenticated attackers, with
contributor-level access and above, to inject arbitrary web scripts in
pages that will execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2187</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2186</p>
</td>
<td rowspan="1" colspan="1">
<p>The Beaver Builder Addons by WPZOOM plugin for WordPress is vulnerable
to Stored Cross-Site Scripting via the Team Members widget in all versions
up to, and including, 1.3.4 due to insufficient input sanitization and
output escaping. This makes it possible for authenticated attackers, with
contributor-level access and above, to inject arbitrary web scripts in
pages that will execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2186</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2185</p>
</td>
<td rowspan="1" colspan="1">
<p>The Beaver Builder Addons by WPZOOM plugin for WordPress is vulnerable
to Stored Cross-Site Scripting via the Image Box widget in all versions
up to, and including, 1.3.4 due to insufficient input sanitization and
output escaping. This makes it possible for authenticated attackers, with
contributor-level access and above, to inject arbitrary web scripts in
pages that will execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2185</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2183</p>
</td>
<td rowspan="1" colspan="1">
<p>The Beaver Builder Addons by WPZOOM plugin for WordPress is vulnerable
to Stored Cross-Site Scripting via the Heading widget in all versions up
to, and including, 1.3.4 due to insufficient input sanitization and output
escaping. This makes it possible for authenticated attackers, with contributor-level
access and above, to inject arbitrary web scripts in pages that will execute
whenever a user accesses an injected page. CVE-2024-30424 is likely a duplicate
of this issue.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2183</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2181</p>
</td>
<td rowspan="1" colspan="1">
<p>The Beaver Builder Addons by WPZOOM plugin for WordPress is vulnerable
to Stored Cross-Site Scripting via the Button widget in all versions up
to, and including, 1.3.4 due to insufficient input sanitization and output
escaping. This makes it possible for authenticated attackers, with contributor-level
access and above, to inject arbitrary web scripts in pages that will execute
whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2181</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2165</p>
</td>
<td rowspan="1" colspan="1">
<p>The SEOPress – On-site SEO plugin for WordPress is vulnerable to Stored
Cross-Site Scripting via the image alt parameter in all versions up to,
and including, 7.5.2.1 due to insufficient input sanitization and output
escaping. This makes it possible for authenticated attackers, with author
access or higher, to inject arbitrary web scripts in pages that will execute
whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2165</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2138</p>
</td>
<td rowspan="1" colspan="1">
<p>The JetWidgets For Elementor plugin for WordPress is vulnerable to Stored
Cross-Site Scripting via the Animated Box widget in all versions up to,
and including, 1.0.15 due to insufficient input sanitization and output
escaping. This makes it possible for authenticated attackers, with contributor-level
access and above, to inject arbitrary web scripts in pages that will execute
whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2138</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2117</p>
</td>
<td rowspan="1" colspan="1">
<p>The Elementor Website Builder – More than Just a Page Builder plugin for
WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's
Path Widget in all versions up to, and including, 3.20.2 due to insufficient
output escaping on user supplied attributes. This makes it possible for
authenticated attackers with contributor-level and above permissions to
inject arbitrary web scripts in pages that will execute whenever a user
accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2117</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2081</p>
</td>
<td rowspan="1" colspan="1">
<p>The Best WordPress Gallery Plugin – FooGallery plugin for WordPress is
vulnerable to Stored Cross-Site Scripting via the foogallery_attachment_modal_save
action in all versions up to, and including, 2.4.14 due to insufficient
input sanitization and output escaping. This makes it possible for authenticated
attackers, with author-level access and above, to inject arbitrary web
scripts in pages that will execute whenever a user accesses an injected
page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2081</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2039</p>
</td>
<td rowspan="1" colspan="1">
<p>The Stackable – Page Builder Gutenberg Blocks plugin for WordPress is
vulnerable to Stored Cross-Site Scripting via the Post(v2) block title
tag in all versions up to, and including, 3.12.11 due to insufficient input
sanitization and output escaping on user supplied attributes. This makes
it possible for authenticated attackers with contributor-level and above
permissions to inject arbitrary web scripts in pages that will execute
whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2039</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2027</p>
</td>
<td rowspan="1" colspan="1">
<p>The Real Media Library: Media Library Folder &amp; File Manager plugin
for WordPress is vulnerable to Stored Cross-Site Scripting via its style
attributes in all versions up to, and including, 4.22.7 due to insufficient
input sanitization and output escaping. This makes it possible for authenticated
attackers, with contributor access or above, to inject arbitrary web scripts
in pages that will execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2027</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2026</p>
</td>
<td rowspan="1" colspan="1">
<p>The Passster plugin for WordPress is vulnerable to Stored Cross-Site Scripting
via the plugin's content_protector shortcode in all versions up to, and
including, 4.2.6.4 due to insufficient input sanitization and output escaping
on user supplied attributes. This makes it possible for authenticated attackers,
with contributor-level access and above, to inject arbitrary web scripts
in pages that will execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2026</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1999</p>
</td>
<td rowspan="1" colspan="1">
<p>The Gutenberg Blocks by Kadence Blocks – Page Builder Features plugin
for WordPress is vulnerable to Stored Cross-Site Scripting via the Testimonial
Widget's anchor style parameter in all versions up to, and including, 3.2.25
due to insufficient input sanitization and output escaping. This makes
it possible for authenticated attackers, with contributor access or higher,
to inject arbitrary web scripts in pages that will execute whenever a user
accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1999</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1960</p>
</td>
<td rowspan="1" colspan="1">
<p>The ShopLentor – WooCommerce Builder for Elementor &amp; Gutenberg +12
Modules – All in One Solution (formerly WooLentor) plugin for WordPress
is vulnerable to Stored Cross-Site Scripting via the Special Offer Day
Widget Banner Link in all versions up to, and including, 2.8.1 due to insufficient
input sanitization and output escaping on user supplied attributes. This
makes it possible for authenticated attackers with contributor-level and
above permissions to inject arbitrary web scripts in pages that will execute
whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1960</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1948</p>
</td>
<td rowspan="1" colspan="1">
<p>The Getwid – Gutenberg Blocks plugin for WordPress is vulnerable to Stored
Cross-Site Scripting via the block content in all versions up to, and including,
2.0.5 due to insufficient input sanitization and output escaping. This
makes it possible for authenticated attackers, with contributor access
and above, to inject arbitrary web scripts in pages that will execute whenever
a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1948</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1498</p>
</td>
<td rowspan="1" colspan="1">
<p>The Happy Addons for Elementor plugin for WordPress is vulnerable to Stored
Cross-Site Scripting via the plugin's Photo Stack Widget in all versions
up to, and including, 3.10.3 due to insufficient input sanitization and
output escaping on user supplied attributes. This makes it possible for
authenticated attackers with contributor-level and above permissions to
inject arbitrary web scripts in pages that will execute whenever a user
accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1498</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1466</p>
</td>
<td rowspan="1" colspan="1">
<p>The Elementor Addons by Livemesh plugin for WordPress is vulnerable to
Stored Cross-Site Scripting via the ‘slider_style’ attribute of the Posts
Multislider widget in all versions up to, and including, 8.3.4 due to insufficient
input sanitization and output escaping. This makes it possible for authenticated
attackers, with contributor-level access and above, to inject arbitrary
web scripts in pages that will execute whenever a user accesses an injected
page. CVE-2024-27986 may be a duplicate of this issue.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1466</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1465</p>
</td>
<td rowspan="1" colspan="1">
<p>The Elementor Addons by Livemesh plugin for WordPress is vulnerable to
Stored Cross-Site Scripting via the ‘carousel_skin’ attribute of the Posts
Carousel widget in all versions up to, and including, 8.3.4 due to insufficient
input sanitization and output escaping. This makes it possible for authenticated
attackers, with contributor-level access and above, to inject arbitrary
web scripts in pages that will execute whenever a user accesses an injected
page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1465</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1464</p>
</td>
<td rowspan="1" colspan="1">
<p>The Elementor Addons by Livemesh plugin for WordPress is vulnerable to
Stored Cross-Site Scripting via the ‘style’ attribute of the Posts Slider
widget in all versions up to, and including, 8.3.4 due to insufficient
input sanitization and output escaping. This makes it possible for authenticated
attackers, with contributor-level access and above, to inject arbitrary
web scripts in pages that will execute whenever a user accesses an injected
page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1464</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1461</p>
</td>
<td rowspan="1" colspan="1">
<p>The Elementor Addons by Livemesh plugin for WordPress is vulnerable to
Stored Cross-Site Scripting via the ‘style’ attribute of the Team Members
widget in all versions up to, and including, 8.3.4 due to insufficient
input sanitization and output escaping. This makes it possible for authenticated
attackers, with contributor-level access and above, to inject arbitrary
web scripts in pages that will execute whenever a user accesses an injected
page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1461</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1458</p>
</td>
<td rowspan="1" colspan="1">
<p>The Elementor Addons by Livemesh plugin for WordPress is vulnerable to
Stored Cross-Site Scripting via the ‘text_alignment’ attribute of the Animated
Text widget in all versions up to, and including, 8.3.4 due to insufficient
input sanitization and output escaping. This makes it possible for authenticated
attackers, with contributor-level access and above, to inject arbitrary
web scripts in pages that will execute whenever a user accesses an injected
page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1458</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1424</p>
</td>
<td rowspan="1" colspan="1">
<p>The GiveWP – Donation Plugin and Fundraising Platform plugin for WordPress
is vulnerable to Stored Cross-Site Scripting via the plugin's shortcode(s)
in all versions up to, and including, 3.5.1 due to insufficient input sanitization
and output escaping on user supplied attributes. This makes it possible
for authenticated attackers with contributor-level and above permissions
to inject arbitrary web scripts in pages that will execute whenever a user
accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1424</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-0873</p>
</td>
<td rowspan="1" colspan="1">
<p>The Watu Quiz plugin for WordPress is vulnerable to Stored Cross-Site
Scripting via the plugin's 'watu-basic-chart' shortcode in all versions
up to, and including, 3.4.1 due to insufficient input sanitization and
output escaping on user supplied attributes. This makes it possible for
authenticated attackers with contributor-level and above permissions to
inject arbitrary web scripts in pages that will execute whenever a user
accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-0873</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-0826</p>
</td>
<td rowspan="1" colspan="1">
<p>The Qi Addons For Elementor plugin for WordPress is vulnerable to Stored
Cross-Site Scripting via the plugin's widgets in all versions up to, and
including, 1.6.7 due to insufficient input sanitization and output escaping
on user supplied attributes. This makes it possible for authenticated attackers
with contributor-level and above permissions to inject arbitrary web scripts
in pages that will execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-0826</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-0376</p>
</td>
<td rowspan="1" colspan="1">
<p>The Premium Addons for Elementor plugin for WordPress is vulnerable to
Stored Cross-Site Scripting via the plugin's Wrapper Link Widget in all
versions up to, and including, 4.10.16 due to insufficient input sanitization
and output escaping on user supplied URLs. This makes it possible for authenticated
attackers with contributor-level and above permissions to inject arbitrary
web scripts in pages that will execute whenever a user accesses an injected
page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-0376</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-6993</p>
</td>
<td rowspan="1" colspan="1">
<p>The Custom post types, Custom Fields &amp; more plugin for WordPress is
vulnerable to Stored Cross-Site Scripting via the plugin's shortcode and
custom post meta in all versions up to, and including, 5.0.4 due to insufficient
input sanitization and output escaping on user supplied post meta values.
This makes it possible for authenticated attackers with contributor-level
and above permissions to inject arbitrary web scripts in pages that will
execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-6993</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-6694</p>
</td>
<td rowspan="1" colspan="1">
<p>The Beaver Themer plugin for WordPress is vulnerable to Stored Cross-Site
Scripting via the plugin's shortcode(s) in all versions up to, and including,
1.4.9 due to insufficient input sanitization and output escaping on user
supplied custom fields. This makes it possible for authenticated attackers
with contributor-level and above permissions to inject arbitrary web scripts
in pages that will execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-6694</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-6486</p>
</td>
<td rowspan="1" colspan="1">
<p>The Spectra – WordPress Gutenberg Blocks plugin for WordPress is vulnerable
to Stored Cross-Site Scripting via the Custom CSS metabox in all versions
up to and including 2.10.3 due to insufficient input sanitization and output
escaping. This makes it possible for authenticated attackers, with contributor-level
access and above, to inject arbitrary web scripts in pages that will execute
whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-6486</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28923</p>
</td>
<td rowspan="1" colspan="1">
<p>Secure Boot Security Feature Bypass Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28923</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26193</p>
</td>
<td rowspan="1" colspan="1">
<p>Azure Migrate Remote Code Execution Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26193</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-6877</p>
</td>
<td rowspan="1" colspan="1">
<p>The RSS Aggregator by Feedzy – Feed to Post, Autoblogging, News &amp;
YouTube Video Feeds Aggregator plugin for WordPress is vulnerable to Stored
Cross-Site Scripting via the plugin's shortcode(s) in all versions up to,
and including, 4.3.3 due to insufficient input sanitization and output
escaping on the Content-Type field of error messages when retrieving an
invalid RSS feed. This makes it possible for authenticated attackers, with
contributor-level access and above, to inject arbitrary web scripts in
pages that will execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-6877</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2132</p>
</td>
<td rowspan="1" colspan="1">
<p>The Ultimate Bootstrap Elements for Elementor plugin for WordPress is
vulnerable to Stored Cross-Site Scripting via the Image Widget in all versions
up to, and including, 1.4.0 due to insufficient input sanitization and
output escaping on user supplied attributes. This makes it possible for
authenticated attackers with contributor-level and above permissions to
inject arbitrary web scripts in pages that will execute whenever a user
accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2132</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2458</p>
</td>
<td rowspan="1" colspan="1">
<p>The Powerkit – Supercharge your WordPress Site plugin for WordPress is
vulnerable to Stored Cross-Site Scripting via the plugin's shortcodes in
all versions up to, and including, 2.9.1 due to insufficient input sanitization
and output escaping on user supplied attributes. This makes it possible
for authenticated attackers with contributor-level and above permissions
to inject arbitrary web scripts in pages that will execute whenever a user
accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2458</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1428</p>
</td>
<td rowspan="1" colspan="1">
<p>The Element Pack Elementor Addons (Header Footer, Free Template Library,
Grid, Carousel, Table, Parallax Animation, Register Form, Twitter Grid)
plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the
‘element_pack_wrapper_link’ attribute of the Trailer Box widget in all
versions up to, and including, 5.5.3 due to insufficient input sanitization
and output escaping. This makes it possible for authenticated attackers,
with contributor-level access and above, to inject arbitrary web scripts
in pages that will execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1428</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-0837</p>
</td>
<td rowspan="1" colspan="1">
<p>The Element Pack Elementor Addons (Header Footer, Free Template Library,
Grid, Carousel, Table, Parallax Animation, Register Form, Twitter Grid)
plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the
image URL parameter in all versions up to, and including, 5.3.2 due to
insufficient input sanitization and output escaping. This makes it possible
for authenticated attackers, with contributor access and above, to inject
arbitrary web scripts in pages that will execute whenever a user accesses
an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-0837</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2949</p>
</td>
<td rowspan="1" colspan="1">
<p>The Carousel, Slider, Gallery by WP Carousel – Image Carousel &amp; Photo
Gallery, Post Carousel &amp; Post Grid, Product Carousel &amp; Product
Grid for WooCommerce plugin for WordPress is vulnerable to Stored Cross-Site
Scripting via the carousel widget in all versions up to, and including,
2.6.3 due to insufficient input sanitization and output escaping on user
supplied attributes. This makes it possible for authenticated attackers,
with contributor-level access and above, to inject arbitrary web scripts
in pages that will execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2949</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2471</p>
</td>
<td rowspan="1" colspan="1">
<p>The FooGallery plugin for WordPress is vulnerable to Stored Cross-Site
Scripting via image attachment fields (such as 'Title', 'Alt Text', 'Custom
URL', 'Custom Class', and 'Override Type') in all versions up to, and including,
2.4.14 due to insufficient input sanitization and output escaping. This
makes it possible for authenticated attackers, with author-level access
and above, to inject arbitrary web scripts in pages that will execute whenever
a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2471</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3245</p>
</td>
<td rowspan="1" colspan="1">
<p>The EmbedPress – Embed PDF, Google Docs, Vimeo, Wistia, Embed YouTube
Videos, Audios, Maps &amp; Embed Any Documents in Gutenberg &amp; Elementor
plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the
plugin's Youtube block in all versions up to, and including, 3.9.14 due
to insufficient input sanitization and output escaping on user supplied
attributes. This makes it possible for authenticated attackers, with contributor-level
access and above, to inject arbitrary web scripts in pages that will execute
whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3245</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2499</p>
</td>
<td rowspan="1" colspan="1">
<p>The Squelch Tabs and Accordions Shortcodes plugin for WordPress is vulnerable
to Stored Cross-Site Scripting via the plugin's 'accordions' shortcode
in all versions up to, and including, 0.4.3 due to insufficient input sanitization
and output escaping on user supplied attributes. This makes it possible
for authenticated attackers, with contributor-level access and above, to
inject arbitrary web scripts in pages that will execute whenever a user
accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2499</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2660</p>
</td>
<td rowspan="1" colspan="1">
<p>Vault and Vault Enterprise TLS certificates auth method did not correctly
validate OCSP responses when one or more OCSP sources were configured.
Fixed in Vault 1.16.0 and Vault Enterprise 1.16.1, 1.15.7, and 1.14.11.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2660</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2919</p>
</td>
<td rowspan="1" colspan="1">
<p>The Gutenberg Blocks by Kadence Blocks – Page Builder Features plugin
for WordPress is vulnerable to Stored Cross-Site Scripting via the Countdown
and CountUp Widget in all versions up to, and including, 3.2.31 due to
insufficient input sanitization and output escaping on user supplied attributes.
This makes it possible for authenticated attackers, with contributor-level
access and above, to inject arbitrary web scripts in pages that will execute
whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2919</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2830</p>
</td>
<td rowspan="1" colspan="1">
<p>The WordPress Tag and Category Manager – AI Autotagger plugin for WordPress
is vulnerable to Stored Cross-Site Scripting via the plugin's 'st_tag_cloud'
shortcode in all versions up to, and including, 3.13.0 due to insufficient
input sanitization and output escaping on user supplied attributes. This
makes it possible for authenticated attackers, with contributor-level access
and above, to inject arbitrary web scripts in pages that will execute whenever
a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2830</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2868</p>
</td>
<td rowspan="1" colspan="1">
<p>The ShopLentor – WooCommerce Builder for Elementor &amp; Gutenberg +12
Modules – All in One Solution (formerly WooLentor) plugin for WordPress
is vulnerable to Stored Cross-Site Scripting via the slitems parameter
in the WL Special Day Offer Widget in all versions up to, and including,
2.8.3 due to insufficient input sanitization and output escaping. This
makes it possible for authenticated attackers, with contributor access
or above, to inject arbitrary web scripts in pages that will execute whenever
a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2868</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2803</p>
</td>
<td rowspan="1" colspan="1">
<p>The ElementsKit Elementor addons plugin for WordPress is vulnerable to
Stored Cross-Site Scripting via the countdown widget in all versions up
to, and including, 3.0.6 due to insufficient input sanitization and output
escaping on user supplied attributes. This makes it possible for authenticated
attackers, with contributor-level access and above, to inject arbitrary
web scripts in pages that will execute whenever a user accesses an injected
page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2803</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3162</p>
</td>
<td rowspan="1" colspan="1">
<p>The Jeg Elementor Kit plugin for WordPress is vulnerable to Stored Cross-Site
Scripting via the Testimonial Widget Attributes in all versions up to,
and including, 2.6.3 due to insufficient input sanitization and output
escaping. This makes it possible for authenticated attackers, with contributor
access or higher, to inject arbitrary web scripts in pages that will execute
whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3162</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1327</p>
</td>
<td rowspan="1" colspan="1">
<p>The Jeg Elementor Kit plugin for WordPress is vulnerable to Stored Cross-Site
Scripting via the plugin's image box widget in all versions up to, and
including, 2.6.3 due to insufficient input sanitization and output escaping.
This makes it possible for authenticated attackers with contributor-level
and above permissions to inject arbitrary web scripts in pages that will
execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1327</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3523</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability classified as critical was found in Campcodes Online Event
Management System 1.0. This vulnerability affects unknown code of the file
/views/index.php. The manipulation of the argument ID leads to sql injection.
The attack can be initiated remotely. The exploit has been disclosed to
the public and may be used. VDB-259894 is the identifier assigned to this
vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3523</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3522</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability classified as critical has been found in Campcodes Online
Event Management System 1.0. This affects an unknown part of the file /api/process.php.
The manipulation of the argument userId leads to sql injection. It is possible
to initiate the attack remotely. The exploit has been disclosed to the
public and may be used. The identifier VDB-259893 was assigned to this
vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3522</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1850</p>
</td>
<td rowspan="1" colspan="1">
<p>The AI Post Generator | AutoWriter plugin for WordPress is vulnerable
to unauthorized access, modification or deletion of posts due to a missing
capability check on functions hooked by AJAX actions in all versions up
to, and including, 3.3. This makes it possible for authenticated attackers,
with subscriber access or higher, to view all posts generated with this
plugin (even in non-published status), create new posts (and publish them),
publish unpublished post or perform post deletions.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1850</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28898</p>
</td>
<td rowspan="1" colspan="1">
<p>Secure Boot Security Feature Bypass Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28898</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3465</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Laundry Management System
1.0. It has been classified as critical. Affected is the function laporan_filter
of the file /application/controller/Transaki.php. The manipulation of the
argument dari/sampai leads to sql injection. It is possible to launch the
attack remotely. The exploit has been disclosed to the public and may be
used. VDB-259746 is the identifier assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3465</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3464</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Laundry Management System
1.0 and classified as critical. This issue affects the function laporan_filter
of the file /application/controller/Pelanggan.php. The manipulation of
the argument jeniskelamin leads to sql injection. The attack may be initiated
remotely. The exploit has been disclosed to the public and may be used.
The identifier VDB-259745 was assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3464</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3458</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability classified as critical was found in Netentsec NS-ASG Application
Security Gateway 6.3. This vulnerability affects unknown code of the file
/admin/add_ikev2.php. The manipulation of the argument TunnelId leads to
sql injection. The attack can be initiated remotely. The exploit has been
disclosed to the public and may be used. VDB-259714 is the identifier assigned
to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3458</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3457</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability classified as critical has been found in Netentsec NS-ASG
Application Security Gateway 6.3. This affects an unknown part of the file
/admin/config_ISCGroupNoCache.php. The manipulation of the argument GroupId
leads to sql injection. It is possible to initiate the attack remotely.
The exploit has been disclosed to the public and may be used. The identifier
VDB-259713 was assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3457</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3456</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in Netentsec NS-ASG Application Security Gateway
6.3. It has been rated as critical. Affected by this issue is some unknown
functionality of the file /admin/config_Anticrack.php. The manipulation
of the argument GroupId leads to sql injection. The attack may be launched
remotely. The exploit has been disclosed to the public and may be used.
The identifier of this vulnerability is VDB-259712.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3456</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3455</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in Netentsec NS-ASG Application Security Gateway
6.3. It has been declared as critical. Affected by this vulnerability is
an unknown functionality of the file /admin/add_postlogin.php. The manipulation
of the argument SingleLoginId leads to sql injection. The attack can be
launched remotely. The exploit has been disclosed to the public and may
be used. The associated identifier of this vulnerability is VDB-259711.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3455</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3445</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Laundry Management System
1.0. It has been declared as critical. This vulnerability affects unknown
code of the file /karyawan/laporan_filter. The manipulation of the argument
data_karyawan leads to sql injection. The attack can be initiated remotely.
The exploit has been disclosed to the public and may be used. VDB-259702
is the identifier assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3445</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3442</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability classified as critical has been found in SourceCodester
Prison Management System 1.0. This affects an unknown part of the file
/Employee/delete_leave.php. The manipulation leads to sql injection. It
is possible to initiate the attack remotely. The exploit has been disclosed
to the public and may be used. The associated identifier of this vulnerability
is VDB-259695.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3442</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3441</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Prison Management System 1.0.
It has been rated as critical. Affected by this issue is some unknown functionality
of the file /Employee/edit-profile.php. The manipulation leads to sql injection.
The attack may be launched remotely. The exploit has been disclosed to
the public and may be used. VDB-259694 is the identifier assigned to this
vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3441</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3436</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Prison Management System 1.0.
It has been declared as critical. This vulnerability affects unknown code
of the file /Admin/edit-photo.php of the component Avatar Handler. The
manipulation of the argument avatar leads to unrestricted upload. The attack
can be initiated remotely. The exploit has been disclosed to the public
and may be used. VDB-259630 is the identifier assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3436</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3425</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability classified as critical was found in SourceCodester Online
Courseware 1.0. Affected by this vulnerability is an unknown functionality
of the file admin/activateall.php. The manipulation of the argument selector
leads to sql injection. The attack can be launched remotely. The exploit
has been disclosed to the public and may be used. The identifier VDB-259597
was assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3425</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3424</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability classified as critical has been found in SourceCodester
Online Courseware 1.0. Affected is an unknown function of the file admin/listscore.php.
The manipulation of the argument title leads to sql injection. It is possible
to launch the attack remotely. The exploit has been disclosed to the public
and may be used. The identifier of this vulnerability is VDB-259596.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3424</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3423</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Online Courseware 1.0. It
has been rated as critical. This issue affects some unknown processing
of the file admin/activateteach.php. The manipulation of the argument selector
leads to sql injection. The attack may be initiated remotely. The exploit
has been disclosed to the public and may be used. The associated identifier
of this vulnerability is VDB-259595.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3423</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3422</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Online Courseware 1.0. It
has been declared as critical. This vulnerability affects unknown code
of the file admin/activatestud.php. The manipulation of the argument selector
leads to sql injection. The attack can be initiated remotely. The exploit
has been disclosed to the public and may be used. VDB-259594 is the identifier
assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3422</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3421</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Online Courseware 1.0. It
has been classified as critical. This affects an unknown part of the file
admin/deactivatestud.php. The manipulation of the argument selector leads
to sql injection. It is possible to initiate the attack remotely. The exploit
has been disclosed to the public and may be used. The identifier VDB-259593
was assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3421</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3420</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Online Courseware 1.0 and
classified as critical. Affected by this issue is some unknown functionality
of the file admin/saveedit.php. The manipulation of the argument id leads
to sql injection. The attack may be launched remotely. The exploit has
been disclosed to the public and may be used. The identifier of this vulnerability
is VDB-259592.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3420</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3419</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability has been found in SourceCodester Online Courseware 1.0
and classified as critical. Affected by this vulnerability is an unknown
functionality of the file admin/edit.php. The manipulation of the argument
id leads to sql injection. The attack can be launched remotely. The exploit
has been disclosed to the public and may be used. The associated identifier
of this vulnerability is VDB-259591.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3419</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3418</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability, which was classified as critical, was found in SourceCodester
Online Courseware 1.0. Affected is an unknown function of the file admin/deactivateteach.php.
The manipulation of the argument selector leads to sql injection. It is
possible to launch the attack remotely. The exploit has been disclosed
to the public and may be used. VDB-259590 is the identifier assigned to
this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3418</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3417</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability, which was classified as critical, has been found in SourceCodester
Online Courseware 1.0. This issue affects some unknown processing of the
file admin/saveeditt.php. The manipulation of the argument contact leads
to sql injection. The attack may be initiated remotely. The exploit has
been disclosed to the public and may be used. The identifier VDB-259589
was assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3417</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3416</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability classified as critical was found in SourceCodester Online
Courseware 1.0. This vulnerability affects unknown code of the file admin/editt.php.
The manipulation of the argument id leads to sql injection. The attack
can be initiated remotely. The exploit has been disclosed to the public
and may be used. The identifier of this vulnerability is VDB-259588.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3416</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3369</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability, which was classified as critical, has been found in code-projects
Car Rental 1.0. Affected by this issue is some unknown functionality of
the file add-vehicle.php. The manipulation of the argument Upload Image
leads to unrestricted upload. The attack may be launched remotely. The
exploit has been disclosed to the public and may be used. VDB-259490 is
the identifier assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3369</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-23592</p>
</td>
<td rowspan="1" colspan="1">
<p>An authentication bypass vulnerability was reported in Lenovo devices
with Synaptics fingerprint readers that could allow an attacker with physical
access to replay fingerprints and bypass Windows Hello authentication.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-23592</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3346</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in Byzoro Smart S80 up to 20240328. It has been
declared as critical. This vulnerability affects unknown code of the file
/log/webmailattach.php. The manipulation of the argument mail_file_path
leads to os command injection. The attack can be initiated remotely. The
exploit has been disclosed to the public and may be used. VDB-259450 is
the identifier assigned to this vulnerability. NOTE: The vendor was contacted
early about this disclosure but did not respond in any way.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3346</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3316</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Computer Laboratory Management
System 1.0. It has been declared as critical. Affected by this vulnerability
is an unknown functionality of the file /admin/category/view_category.php.
The manipulation of the argument id leads to sql injection. The attack
can be launched remotely. The exploit has been disclosed to the public
and may be used. The associated identifier of this vulnerability is VDB-259387.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3316</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3315</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Computer Laboratory Management
System 1.0. It has been classified as critical. Affected is an unknown
function of the file classes/user.php. The manipulation of the argument
id leads to sql injection. It is possible to launch the attack remotely.
The exploit has been disclosed to the public and may be used. VDB-259386
is the identifier assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3315</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3314</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Computer Laboratory Management
System 1.0 and classified as critical. This issue affects some unknown
processing of the file /classes/Users.php. The manipulation leads to sql
injection. The attack may be initiated remotely. The identifier VDB-259385
was assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3314</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3311</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in Dreamer CMS up to 4.1.3.0. It has been declared
as critical. Affected by this vulnerability is the function ZipUtils.unZipFiles
of the file controller/admin/<a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">ThemesController.java</a>. The manipulation
leads to path traversal. The attack can be launched remotely. The exploit
has been disclosed to the public and may be used. Upgrading to version
4.1.3.1 is able to address this issue. It is recommended to upgrade the
affected component. The identifier VDB-259369 was assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3311</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31215</p>
</td>
<td rowspan="1" colspan="1">
<p>Mobile Security Framework (MobSF) is a security research platform for
mobile applications in Android, iOS and Windows Mobile.
<br>A SSRF vulnerability in firebase database check logic. The attacker can
cause the server to make a connection to internal-only services within
the organization’s infrastructure. When a malicious app is uploaded to
Static analyzer, it is possible to make internal requests. This vulnerability
has been patched in version 3.9.8.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31215</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3259</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Internship Portal Management
System 1.0. It has been declared as critical. This vulnerability affects
unknown code of the file admin/delete_activity.php. The manipulation of
the argument activity_id leads to sql injection. The attack can be initiated
remotely. The exploit has been disclosed to the public and may be used.
The identifier of this vulnerability is VDB-259108.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3259</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3258</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Internship Portal Management
System 1.0. It has been classified as critical. This affects an unknown
part of the file admin/add_activity.php. The manipulation of the argument
title/description/start/end leads to sql injection. It is possible to initiate
the attack remotely. The exploit has been disclosed to the public and may
be used. The associated identifier of this vulnerability is VDB-259107.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3258</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3257</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Internship Portal Management
System 1.0 and classified as critical. Affected by this issue is some unknown
functionality of the file admin/edit_activity_query.php. The manipulation
of the argument title/description/start/end leads to sql injection. The
attack may be launched remotely. The exploit has been disclosed to the
public and may be used. VDB-259106 is the identifier assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3257</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3256</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability has been found in SourceCodester Internship Portal Management
System 1.0 and classified as critical. Affected by this vulnerability is
an unknown functionality of the file admin/edit_activity.php. The manipulation
of the argument activity_id leads to sql injection. The attack can be launched
remotely. The exploit has been disclosed to the public and may be used.
The identifier VDB-259105 was assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3256</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3255</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability, which was classified as critical, was found in SourceCodester
Internship Portal Management System 1.0. Affected is an unknown function
of the file admin/edit_admin_query.php. The manipulation of the argument
username/password/name/admin_id leads to sql injection. It is possible
to launch the attack remotely. The exploit has been disclosed to the public
and may be used. The identifier of this vulnerability is VDB-259104.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3255</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3254</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability, which was classified as critical, has been found in SourceCodester
Internship Portal Management System 1.0. This issue affects some unknown
processing of the file admin/edit_admin.php. The manipulation of the argument
admin_id leads to sql injection. The attack may be initiated remotely.
The exploit has been disclosed to the public and may be used. The associated
identifier of this vulnerability is VDB-259103.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3254</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28782</p>
</td>
<td rowspan="1" colspan="1">
<p>IBM QRadar Suite Software 1.10.12.0 through 1.10.18.0 and IBM Cloud Pak
for Security 1.10.0.0 through 1.10.11.0 stores user credentials in plain
clear text which can be read by an authenticated user. IBM X-Force ID:
285698.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28782</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3253</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability classified as critical was found in SourceCodester Internship
Portal Management System 1.0. This vulnerability affects unknown code of
the file admin/add_admin.php. The manipulation of the argument name/username/password
leads to sql injection. The attack can be initiated remotely. The exploit
has been disclosed to the public and may be used. VDB-259102 is the identifier
assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3253</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3252</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability classified as critical has been found in SourceCodester
Internship Portal Management System 1.0. This affects an unknown part of
the file admin/check_admin.php. The manipulation of the argument username/password
leads to sql injection. It is possible to initiate the attack remotely.
The exploit has been disclosed to the public and may be used. The identifier
VDB-259101 was assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3252</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3251</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Computer Laboratory Management
System 1.0. It has been rated as critical. Affected by this issue is some
unknown functionality of the file /admin/?page=borrow/view_borrow. The
manipulation of the argument id leads to sql injection. The attack may
be launched remotely. The exploit has been disclosed to the public and
may be used. The identifier of this vulnerability is VDB-259100.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3251</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3225</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester PHP Task Management System
1.0 and classified as critical. Affected by this issue is some unknown
functionality of the file edit-task.php. The manipulation of the argument
task_id leads to sql injection. The attack may be launched remotely. The
exploit has been disclosed to the public and may be used. VDB-259070 is
the identifier assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3225</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3224</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability has been found in SourceCodester PHP Task Management System
1.0 and classified as critical. Affected by this vulnerability is an unknown
functionality of the file task-details.php. The manipulation of the argument
task_id leads to sql injection. The attack can be launched remotely. The
exploit has been disclosed to the public and may be used. The identifier
VDB-259069 was assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3224</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3223</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability, which was classified as critical, was found in SourceCodester
PHP Task Management System 1.0. Affected is an unknown function of the
file admin-manage-user.php. The manipulation of the argument admin_id leads
to sql injection. It is possible to launch the attack remotely. The exploit
has been disclosed to the public and may be used. The identifier of this
vulnerability is VDB-259068.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3223</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3222</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability, which was classified as critical, has been found in SourceCodester
PHP Task Management System 1.0. This issue affects some unknown processing
of the file admin-password-change.php. The manipulation of the argument
admin_id leads to sql injection. The attack may be initiated remotely.
The exploit has been disclosed to the public and may be used. The associated
identifier of this vulnerability is VDB-259067.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3222</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3221</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability classified as critical was found in SourceCodester PHP
Task Management System 1.0. This vulnerability affects unknown code of
the file attendance-info.php. The manipulation of the argument user_id
leads to sql injection. The attack can be initiated remotely. The exploit
has been disclosed to the public and may be used. VDB-259066 is the identifier
assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3221</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29064</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Hyper-V Denial of Service Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>6.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29064</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28917</p>
</td>
<td rowspan="1" colspan="1">
<p>Azure Arc-enabled Kubernetes Extension Cluster-Scope Elevation of Privilege
Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>6.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28917</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-50821</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability has been identified in SIMATIC PCS 7 V9.1 (All versions
&lt; V9.1 SP2 UC04), SIMATIC WinCC Runtime Professional V17 (All versions),
SIMATIC WinCC Runtime Professional V18 (All versions), SIMATIC WinCC Runtime
Professional V19 (All versions &lt; V19 Update 1), SIMATIC WinCC V7.5 (All
versions &lt; V7.5 SP2 Update 16), SIMATIC WinCC V8.0 (All versions). The
affected products do not properly validate the input provided in the login
dialog box. An attacker could leverage this vulnerability to cause a persistent
denial of service condition.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-50821</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30270</p>
</td>
<td rowspan="1" colspan="1">
<p>mailcow: dockerized is an open source groupware/email suite based on docker.
A security vulnerability has been identified in mailcow affecting versions
prior to 2024-04. This vulnerability is a combination of path traversal
and arbitrary code execution, specifically targeting the <code>rspamd_maps()</code> function.
It allows authenticated admin users to overwrite any file writable by the
www-data user by exploiting improper path validation. The exploit chain
can lead to the execution of arbitrary commands on the server. Version
2024-04 contains a patch for the issue.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30270</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-25030</p>
</td>
<td rowspan="1" colspan="1">
<p>IBM Db2 for Linux, UNIX and Windows (includes Db2 Connect Server) 11.1
stores potentially sensitive information in log files that could be read
by a local user. IBM X-Force ID: 281677.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-25030</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2738</p>
</td>
<td rowspan="1" colspan="1">
<p>The Permalink Manager Lite and Pro plugins for WordPress are vulnerable
to Reflected Cross-Site Scripting via the ‘s’ parameter in multiple instances
in all versions up to, and including, 2.4.3.1 due to insufficient input
sanitization and output escaping. This makes it possible for unauthenticated
attackers to inject arbitrary web scripts in pages that execute if they
can successfully trick a user into performing an action such as clicking
on a link.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2738</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2325</p>
</td>
<td rowspan="1" colspan="1">
<p>The Link Library plugin for WordPress is vulnerable to Reflected Cross-Site
Scripting via the searchll parameter in all versions up to, and including,
7.6.6 due to insufficient input sanitization and output escaping. This
makes it possible for unauthenticated attackers to inject arbitrary web
scripts in pages that execute if they can successfully trick a user into
performing an action such as clicking on a link.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2325</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2200</p>
</td>
<td rowspan="1" colspan="1">
<p>The Contact Form by BestWebSoft plugin for WordPress is vulnerable to
Reflected Cross-Site Scripting via the ‘cntctfrm_contact_subject’ parameter
in all versions up to, and including, 4.2.8 due to insufficient input sanitization
and output escaping. This makes it possible for unauthenticated attackers
to inject arbitrary web scripts in pages that execute if they can successfully
trick a user into performing an action such as clicking on a link.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2200</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2198</p>
</td>
<td rowspan="1" colspan="1">
<p>The Contact Form by BestWebSoft plugin for WordPress is vulnerable to
Reflected Cross-Site Scripting via the ‘cntctfrm_contact_address’ parameter
in all versions up to, and including, 4.2.8 due to insufficient input sanitization
and output escaping. This makes it possible for unauthenticated attackers
to inject arbitrary web scripts in pages that execute if they can successfully
trick a user into performing an action such as clicking on a link.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2198</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1412</p>
</td>
<td rowspan="1" colspan="1">
<p>The Memberpress plugin for WordPress is vulnerable to Reflected Cross-Site
Scripting via the ‘message’ and 'error' parameters in all versions up to,
and including, 1.11.26 due to insufficient input sanitization and output
escaping. This makes it possible for unauthenticated attackers to inject
arbitrary web scripts in pages that execute if they can successfully trick
a user into performing an action such as clicking on a link. Note - the
issue was partially patched in 1.11.25, but could still potentially be
exploited under some circumstances.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1412</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2022-4965</p>
</td>
<td rowspan="1" colspan="1">
<p>The Invitation Code Content Restriction Plugin from CreativeMinds plugin
for WordPress is vulnerable to Reflected Cross-Site Scripting via the ‘target_id’
parameter in all versions up to, and including, 1.5.4 due to insufficient
input sanitization and output escaping. This makes it possible for unauthenticated
attackers to inject arbitrary web scripts in pages that execute if they
can successfully trick a user into performing an action such as clicking
on a link.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2022-4965</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-20665</p>
</td>
<td rowspan="1" colspan="1">
<p>BitLocker Security Feature Bypass Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>6.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-20665</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30190</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability has been identified in SCALANCE W1748-1 M12 (6GK5748-1GY01-0AA0),
SCALANCE W1748-1 M12 (6GK5748-1GY01-0TA0), SCALANCE W1788-1 M12 (6GK5788-1GY01-0AA0),
SCALANCE W1788-2 EEC M12 (6GK5788-2GY01-0TA0), SCALANCE W1788-2 M12 (6GK5788-2GY01-0AA0),
SCALANCE W1788-2IA M12 (6GK5788-2HY01-0AA0), SCALANCE W721-1 RJ45 (6GK5721-1FC00-0AA0),
SCALANCE W721-1 RJ45 (6GK5721-1FC00-0AB0), SCALANCE W722-1 RJ45 (6GK5722-1FC00-0AA0),
SCALANCE W722-1 RJ45 (6GK5722-1FC00-0AB0), SCALANCE W722-1 RJ45 (6GK5722-1FC00-0AC0),
SCALANCE W734-1 RJ45 (6GK5734-1FX00-0AA0), SCALANCE W734-1 RJ45 (6GK5734-1FX00-0AA6),
SCALANCE W734-1 RJ45 (6GK5734-1FX00-0AB0), SCALANCE W734-1 RJ45 (USA) (6GK5734-1FX00-0AB6),
SCALANCE W738-1 M12 (6GK5738-1GY00-0AA0), SCALANCE W738-1 M12 (6GK5738-1GY00-0AB0),
SCALANCE W748-1 M12 (6GK5748-1GD00-0AA0), SCALANCE W748-1 M12 (6GK5748-1GD00-0AB0),
SCALANCE W748-1 RJ45 (6GK5748-1FC00-0AA0), SCALANCE W748-1 RJ45 (6GK5748-1FC00-0AB0),
SCALANCE W761-1 RJ45 (6GK5761-1FC00-0AA0), SCALANCE W761-1 RJ45 (6GK5761-1FC00-0AB0),
SCALANCE W774-1 M12 EEC (6GK5774-1FY00-0TA0), SCALANCE W774-1 M12 EEC (6GK5774-1FY00-0TB0),
SCALANCE W774-1 RJ45 (6GK5774-1FX00-0AA0), SCALANCE W774-1 RJ45 (6GK5774-1FX00-0AA6),
SCALANCE W774-1 RJ45 (6GK5774-1FX00-0AB0), SCALANCE W774-1 RJ45 (6GK5774-1FX00-0AC0),
SCALANCE W774-1 RJ45 (USA) (6GK5774-1FX00-0AB6), SCALANCE W778-1 M12 (6GK5778-1GY00-0AA0),
SCALANCE W778-1 M12 (6GK5778-1GY00-0AB0), SCALANCE W778-1 M12 EEC (6GK5778-1GY00-0TA0),
SCALANCE W778-1 M12 EEC (USA) (6GK5778-1GY00-0TB0), SCALANCE W786-1 RJ45
(6GK5786-1FC00-0AA0), SCALANCE W786-1 RJ45 (6GK5786-1FC00-0AB0), SCALANCE
W786-2 RJ45 (6GK5786-2FC00-0AA0), SCALANCE W786-2 RJ45 (6GK5786-2FC00-0AB0),
SCALANCE W786-2 RJ45 (6GK5786-2FC00-0AC0), SCALANCE W786-2 SFP (6GK5786-2FE00-0AA0),
SCALANCE W786-2 SFP (6GK5786-2FE00-0AB0), SCALANCE W786-2IA RJ45 (6GK5786-2HC00-0AA0),
SCALANCE W786-2IA RJ45 (6GK5786-2HC00-0AB0), SCALANCE W788-1 M12 (6GK5788-1GD00-0AA0),
SCALANCE W788-1 M12 (6GK5788-1GD00-0AB0), SCALANCE W788-1 RJ45 (6GK5788-1FC00-0AA0),
SCALANCE W788-1 RJ45 (6GK5788-1FC00-0AB0), SCALANCE W788-2 M12 (6GK5788-2GD00-0AA0),
SCALANCE W788-2 M12 (6GK5788-2GD00-0AB0), SCALANCE W788-2 M12 EEC (6GK5788-2GD00-0TA0),
SCALANCE W788-2 M12 EEC (6GK5788-2GD00-0TB0), SCALANCE W788-2 M12 EEC (6GK5788-2GD00-0TC0),
SCALANCE W788-2 RJ45 (6GK5788-2FC00-0AA0), SCALANCE W788-2 RJ45 (6GK5788-2FC00-0AB0),
SCALANCE W788-2 RJ45 (6GK5788-2FC00-0AC0), SCALANCE WAM763-1 (6GK5763-1AL00-7DA0),
SCALANCE WAM766-1 (EU) (6GK5766-1GE00-7DA0), SCALANCE WAM766-1 (US) (6GK5766-1GE00-7DB0),
SCALANCE WAM766-1 EEC (EU) (6GK5766-1GE00-7TA0), SCALANCE WAM766-1 EEC
(US) (6GK5766-1GE00-7TB0), SCALANCE WUM763-1 (6GK5763-1AL00-3AA0), SCALANCE
WUM763-1 (6GK5763-1AL00-3DA0), SCALANCE WUM766-1 (EU) (6GK5766-1GE00-3DA0),
SCALANCE WUM766-1 (US) (6GK5766-1GE00-3DB0). This CVE refers to Scenario
2 "Abuse the queue for network disruptions" of CVE-2022-47522.\r
<br>\r
<br>Affected devices can be tricked into enabling its power-saving mechanisms
for a victim client. This could allow a physically proximate attacker to
execute disconnection and denial-of-service attacks.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30190</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30189</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability has been identified in SCALANCE W721-1 RJ45 (6GK5721-1FC00-0AA0)
(All versions), SCALANCE W721-1 RJ45 (6GK5721-1FC00-0AB0) (All versions),
SCALANCE W722-1 RJ45 (6GK5722-1FC00-0AA0) (All versions), SCALANCE W722-1
RJ45 (6GK5722-1FC00-0AB0) (All versions), SCALANCE W722-1 RJ45 (6GK5722-1FC00-0AC0)
(All versions), SCALANCE W734-1 RJ45 (6GK5734-1FX00-0AA0) (All versions),
SCALANCE W734-1 RJ45 (6GK5734-1FX00-0AA6) (All versions), SCALANCE W734-1
RJ45 (6GK5734-1FX00-0AB0) (All versions), SCALANCE W734-1 RJ45 (USA) (6GK5734-1FX00-0AB6)
(All versions), SCALANCE W738-1 M12 (6GK5738-1GY00-0AA0) (All versions),
SCALANCE W738-1 M12 (6GK5738-1GY00-0AB0) (All versions), SCALANCE W748-1
M12 (6GK5748-1GD00-0AA0) (All versions), SCALANCE W748-1 M12 (6GK5748-1GD00-0AB0)
(All versions), SCALANCE W748-1 RJ45 (6GK5748-1FC00-0AA0) (All versions),
SCALANCE W748-1 RJ45 (6GK5748-1FC00-0AB0) (All versions), SCALANCE W761-1
RJ45 (6GK5761-1FC00-0AA0) (All versions), SCALANCE W761-1 RJ45 (6GK5761-1FC00-0AB0)
(All versions), SCALANCE W774-1 M12 EEC (6GK5774-1FY00-0TA0) (All versions),
SCALANCE W774-1 M12 EEC (6GK5774-1FY00-0TB0) (All versions), SCALANCE W774-1
RJ45 (6GK5774-1FX00-0AA0) (All versions), SCALANCE W774-1 RJ45 (6GK5774-1FX00-0AA6)
(All versions), SCALANCE W774-1 RJ45 (6GK5774-1FX00-0AB0) (All versions),
SCALANCE W774-1 RJ45 (6GK5774-1FX00-0AC0) (All versions), SCALANCE W774-1
RJ45 (USA) (6GK5774-1FX00-0AB6) (All versions), SCALANCE W778-1 M12 (6GK5778-1GY00-0AA0)
(All versions), SCALANCE W778-1 M12 (6GK5778-1GY00-0AB0) (All versions),
SCALANCE W778-1 M12 EEC (6GK5778-1GY00-0TA0) (All versions), SCALANCE W778-1
M12 EEC (USA) (6GK5778-1GY00-0TB0) (All versions), SCALANCE W786-1 RJ45
(6GK5786-1FC00-0AA0) (All versions), SCALANCE W786-1 RJ45 (6GK5786-1FC00-0AB0)
(All versions), SCALANCE W786-2 RJ45 (6GK5786-2FC00-0AA0) (All versions),
SCALANCE W786-2 RJ45 (6GK5786-2FC00-0AB0) (All versions), SCALANCE W786-2
RJ45 (6GK5786-2FC00-0AC0) (All versions), SCALANCE W786-2 SFP (6GK5786-2FE00-0AA0)
(All versions), SCALANCE W786-2 SFP (6GK5786-2FE00-0AB0) (All versions),
SCALANCE W786-2IA RJ45 (6GK5786-2HC00-0AA0) (All versions), SCALANCE W786-2IA
RJ45 (6GK5786-2HC00-0AB0) (All versions), SCALANCE W788-1 M12 (6GK5788-1GD00-0AA0)
(All versions), SCALANCE W788-1 M12 (6GK5788-1GD00-0AB0) (All versions),
SCALANCE W788-1 RJ45 (6GK5788-1FC00-0AA0) (All versions), SCALANCE W788-1
RJ45 (6GK5788-1FC00-0AB0) (All versions), SCALANCE W788-2 M12 (6GK5788-2GD00-0AA0)
(All versions), SCALANCE W788-2 M12 (6GK5788-2GD00-0AB0) (All versions),
SCALANCE W788-2 M12 EEC (6GK5788-2GD00-0TA0) (All versions), SCALANCE W788-2
M12 EEC (6GK5788-2GD00-0TB0) (All versions), SCALANCE W788-2 M12 EEC (6GK5788-2GD00-0TC0)
(All versions), SCALANCE W788-2 RJ45 (6GK5788-2FC00-0AA0) (All versions),
SCALANCE W788-2 RJ45 (6GK5788-2FC00-0AB0) (All versions), SCALANCE W788-2
RJ45 (6GK5788-2FC00-0AC0) (All versions). This CVE refers to Scenario 1
"Leak frames from the Wi-Fi queue" of CVE-2022-47522.\r
<br>\r
<br>Affected devices queue frames in order to subsequently change the security
context and leak the queued frames. This could allow a physically proximate
attacker to intercept (possibly cleartext) target-destined frames.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30189</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-23192</p>
</td>
<td rowspan="1" colspan="1">
<p>RSS feeds that contain malicious data- attributes could be abused to inject
script code to a users browser session when reading compromised RSS feeds
or successfully luring users to compromised accounts. Attackers could perform
malicious API requests or extract information from the users account. Please
deploy the provided updates and patch releases. Potentially malicious attributes
now get removed from external RSS content. No publicly available exploits
are known.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-23192</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-0406</p>
</td>
<td rowspan="1" colspan="1">
<p>A flaw was discovered in the mholt/archiver package. This flaw allows
an attacker to create a specially crafted tar file, which, when unpacked,
may allow access to restricted files or directories. This issue can allow
the creation or overwriting of files with the user's or application's privileges
using the library.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-0406</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31204</p>
</td>
<td rowspan="1" colspan="1">
<p>mailcow: dockerized is an open source groupware/email suite based on docker.
A security vulnerability has been identified in mailcow affecting versions
prior to 2024-04. This vulnerability resides in the exception handling
mechanism, specifically when not operating in DEV_MODE. The system saves
exception details into a session array without proper sanitization or encoding.
These details are later rendered into HTML and executed in a JavaScript
block within the user's browser, without adequate escaping of HTML entities.
This flaw allows for Cross-Site Scripting (XSS) attacks, where attackers
can inject malicious scripts into the admin panel by triggering exceptions
with controlled input. The exploitation method involves using any function
that might throw an exception with user-controllable argument. This issue
can lead to session hijacking and unauthorized administrative actions,
posing a significant security risk. Version 2024-04 contains a fix for
the issue.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31204</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29193</p>
</td>
<td rowspan="1" colspan="1">
<p>gotortc is a camera streaming application. Versions 1.8.5 and prior are
vulnerable to DOM-based cross-site scripting. The index page (`index.html`)
shows the available streams by fetching the API (`[0]`) in the client side.
Then, it uses <code>Object.entries</code> to iterate over the result (`[1]`)
whose first item (`name`) gets appended using <code>innerHTML</code> (`[2]`).
In the event of a victim visiting the server in question, their browser
will execute the request against the go2rtc instance. After the request,
the browser will be redirected to go2rtc, in which the XSS would be executed
in the context of go2rtc’s origin. As of time of publication, no patch
is available.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29193</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-25709</p>
</td>
<td rowspan="1" colspan="1">
<p>There is a stored Cross-site Scripting vulnerability in Esri Portal for
ArcGIS versions 10.8.1 – 1121 that may allow a remote, authenticated attacker
to create a crafted link that can be saved as a new location when moving
an existing item which will potentially execute arbitrary JavaScript code
in the victim’s browser. The privileges required to execute this attack
are high.&nbsp;</p>
</td>
<td rowspan="1" colspan="1">
<p>6.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-25709</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-25706</p>
</td>
<td rowspan="1" colspan="1">
<p>There is an HTML injection vulnerability in Esri Portal for ArcGIS &lt;=11.0
that may allow a remote, unauthenticated attacker to craft a URL which,
when clicked, could potentially generate a message that may entice an unsuspecting
victim to visit an arbitrary website. This could simplify phishing attacks.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-25706</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-25703</p>
</td>
<td rowspan="1" colspan="1">
<p>There is a reflected cross site scripting vulnerability in the home application
in Esri Portal for ArcGIS 11.1 and below on Windows and Linux that allows
a remote, unauthenticated attacker to create a crafted link which when
clicked could potentially execute arbitrary JavaScript code in the victim’s
browser.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-25703</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-25698</p>
</td>
<td rowspan="1" colspan="1">
<p>There is a reflected cross site scripting vulnerability in the home application
in Esri Portal for ArcGIS 11.1 and below on Windows and Linux that allows
a remote, unauthenticated attacker to create a crafted link which when
clicked could potentially execute arbitrary JavaScript code in the victim’s
browser.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-25698</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29191</p>
</td>
<td rowspan="1" colspan="1">
<p>gotortc is a camera streaming application. Versions 1.8.5 and prior are
vulnerable to DOM-based cross-site scripting. The links page (`links.html`)
appends the <code>src</code> GET parameter (`[0]`) in all of its links for
1-click previews. The context in which <code>src</code> is being appended
is <code>innerHTML</code> (`[1]`), which will insert the text as HTML. Commit
3b3d5b033aac3a019af64f83dec84f70ed2c8aba contains a patch for the issue.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29191</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29182</p>
</td>
<td rowspan="1" colspan="1">
<p>Collabora Online is a collaborative online office suite based on LibreOffice.
A stored cross-site scripting vulnerability was found in Collabora Online.
An attacker could create a document with an XSS payload in document text
referenced by field which, if hovered over to produce a tooltip, could
be executed by the user's browser. Users should upgrade to Collabora Online
23.05.10.1 or higher. Earlier series of Collabora Online, 22.04, 21.11,
etc. are unaffected.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29182</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-20362</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability in the web-based management interface of Cisco Small Business
RV016, RV042, RV042G, RV082, RV320, and RV325 Routers could allow an unauthenticated,
remote attacker to conduct a cross-site scripting (XSS) attack against
a user of the interface.\r
<br>\r This vulnerability is due to insufficient input validation by the web-based
management interface. An attacker could exploit this vulnerability by persuading
a user to visit specific web pages that include malicious payloads. A successful
exploit could allow the attacker to execute arbitrary script code in the
context of the affected interface or access sensitive, browser-based information.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-20362</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-20310</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability in the web-based interface of Cisco Unified Communications
Manager IM &amp; Presence Service (Unified CM IM&amp;P) could allow an
unauthenticated, remote attacker to conduct a cross-site scripting (XSS)
attack against an authenticated user of the interface.\r
<br>\r This vulnerability exists because the web-based management interface
does not properly validate user-supplied input. An attacker could exploit
this vulnerability by persuading an authenticated user of the interface
to click a crafted link. A successful exploit could allow the attacker
to execute arbitrary script code in the context of the affected interface
or access sensitive browser-based information.</p>
</td>
<td rowspan="1" colspan="1">
<p>6.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-20310</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-20282</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability in Cisco Nexus Dashboard could allow an authenticated,
local attacker with valid rescue-user credentials to elevate privileges
to root on an affected device.\r
<br>\r This vulnerability is due to insufficient protections for a sensitive
access token. An attacker could exploit this vulnerability by using this
token to access resources within the device infrastructure. A successful
exploit could allow an attacker to gain root access to the filesystem or
hosted containers on an affected device.</p>
</td>
<td rowspan="1" colspan="1">
<p>6</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-20282</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2112</p>
</td>
<td rowspan="1" colspan="1">
<p>The Form Maker by 10Web – Mobile-Friendly Drag &amp; Drop Contact Form
Builder plugin for WordPress is vulnerable to Sensitive Information Exposure
in all versions up to, and including, 1.15.22 via the signature functionality.
This makes it possible for unauthenticated attackers to extract sensitive
data including user signatures.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2112</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-6799</p>
</td>
<td rowspan="1" colspan="1">
<p>The WP Reset – Most Advanced WordPress Reset Tool plugin for WordPress
is vulnerable to Sensitive Information Exposure in all versions up to,
and including, 1.99 via the use of insufficiently random snapshot names.
This makes it possible for unauthenticated attackers to extract sensitive
data including site backups by brute-forcing the snapshot filenames.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-6799</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-24694</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper privilege management in the installer for Zoom Desktop Client
for Windows before version 5.17.10 may allow an authenticated user to conduct
an escalation of privilege via local access.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-24694</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30262</p>
</td>
<td rowspan="1" colspan="1">
<p>Contao is an open source content management system. Prior to version 4.13.40,
when a frontend member changes their password in the personal data or the
password lost module, the corresponding remember-me tokens are not removed.
If someone compromises an account and is able to get a remember-me token,
changing the password would not be enough to reclaim control over the account.
Version 4.13.40 contains a fix for the issue. As a workaround, disable
"Allow auto login" in the login module.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30262</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-20685</p>
</td>
<td rowspan="1" colspan="1">
<p>Azure Private 5G Core Denial of Service Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>5.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-20685</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31487</p>
</td>
<td rowspan="1" colspan="1">
<p>A improper limitation of a pathname to a restricted directory ('path traversal')
in Fortinet FortiSandbox version 4.4.0 through 4.4.4 and 4.2.0 through
4.2.6 and 4.0.0 through 4.0.5 and 3.2.0 through 3.2.4 and 3.1.0 through
3.1.5 and 3.0.0 through 3.0.7 and 2.5.0 through 2.5.2 and 2.4.0 through
2.4.1 may allows attacker to information disclosure via crafted http requests.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31487</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31221</p>
</td>
<td rowspan="1" colspan="1">
<p>Sunshine is a self-hosted game stream host for Moonlight. Starting in
version 0.10.0 and prior to version 0.23.0, after unpairing all devices
in the web UI interface and then pairing only one device, all of the previously
devices will be temporarily paired. Version 0.23.0 contains a patch for
the issue. As a workaround, restarting Sunshine after unpairing all devices
prevents the vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31221</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31344</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Neutralization of Input During Web Page Generation ('Cross-site
Scripting') vulnerability in Phpbits Creative Studio Easy Login Styler
– White Label Admin Login Page for WordPress allows Stored XSS.This issue
affects Easy Login Styler – White Label Admin Login Page for WordPress:
from n/a through 1.0.6.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>5.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31344</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27268</p>
</td>
<td rowspan="1" colspan="1">
<p>IBM WebSphere Application Server Liberty 18.0.0.2 through 24.0.0.3 is
vulnerable to a denial of service, caused by sending a specially crafted
request. A remote attacker could exploit this vulnerability to cause the
server to consume memory resources. IBM X-Force ID: 284574.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27268</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31207</p>
</td>
<td rowspan="1" colspan="1">
<p>Vite (French word for "quick", pronounced /vit/, like "veet") is a frontend
build tooling to improve the frontend development experience.`server.fs.deny`
does not deny requests for patterns with directories. This vulnerability
has been patched in version(s) 5.2.6, 5.1.7, 5.0.13, 4.5.3, 3.2.10 and
2.9.18.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31207</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3296</p>
</td>
<td rowspan="1" colspan="1">
<p>A timing-based side-channel flaw exists in the rust-openssl package, which
could be sufficient to recover a plaintext across a network in a Bleichenbacher-style
attack. To achieve successful decryption, an attacker would have to be
able to send a large number of trial messages for decryption. The vulnerability
affects the legacy PKCS#1v1.5 RSA encryption padding mode.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3296</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3214</p>
</td>
<td rowspan="1" colspan="1">
<p>The Relevanssi – A Better Search plugin for WordPress is vulnerable to
CSV Injection in all versions up to, and including, 4.22.1. This makes
it possible for unauthenticated attackers to embed untrusted input into
exported CSV files, which can result in code execution when these files
are downloaded and opened on a local system with a vulnerable configuration.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3214</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30254</p>
</td>
<td rowspan="1" colspan="1">
<p>MesonLSP is an unofficial, unendorsed language server for meson written
in C++. A vulnerability in versions prior to 4.1.4 allows overwriting arbitrary
files if the attacker can make the victim either run the language server
within a specific crafted project or <code>mesonlsp --full</code>. Version
4.1.4 contains a patch for this issue. As a workaround, avoid running <code>mesonlsp --full</code> and
set the language server option <code>others.neverDownloadAutomatically</code> to <code>true</code>.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>5.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30254</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27247</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper privilege management in the installer for Zoom Desktop Client
for macOS before version 5.17.10 may allow a privileged user to conduct
an escalation of privilege via local access.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27247</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-25116</p>
</td>
<td rowspan="1" colspan="1">
<p>RedisBloom adds a set of probabilistic data structures to Redis. Starting
in version 2.0.0 and prior to version 2.4.7 and 2.6.10, authenticated users
can use the <code>CF.RESERVE</code> command to trigger a runtime assertion
and termination of the Redis server process. The problem is fixed in RedisBloom
2.4.7 and 2.6.10.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-25116</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29992</p>
</td>
<td rowspan="1" colspan="1">
<p>Azure Identity Library for .NET Information Disclosure Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>5.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29992</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28902</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Remote Access Connection Manager Information Disclosure Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>5.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28902</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28901</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Remote Access Connection Manager Information Disclosure Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>5.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28901</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28900</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Remote Access Connection Manager Information Disclosure Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>5.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28900</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26255</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Remote Access Connection Manager Information Disclosure Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>5.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26255</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26217</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Remote Access Connection Manager Information Disclosure Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>5.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26217</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26209</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft Local Security Authority Subsystem Service Information Disclosure
Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>5.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26209</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26207</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Remote Access Connection Manager Information Disclosure Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>5.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26207</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26172</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows DWM Core Library Information Disclosure Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>5.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26172</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3466</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Laundry Management System
1.0. It has been declared as critical. Affected by this vulnerability is
the function laporan_filter of the file /application/controller/Pengeluaran.php.
The manipulation of the argument dari/sampai leads to sql injection. The
associated identifier of this vulnerability is VDB-259747.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3466</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3432</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in PuneethReddyHC Event Management 1.0. It has
been rated as critical. This issue affects some unknown processing of the
file /backend/register.php. The manipulation of the argument event_id/full_name/email/mobile/college/branch
leads to sql injection. The attack may be initiated remotely. The exploit
has been disclosed to the public and may be used. The identifier VDB-259613
was assigned to this vulnerability. NOTE: The vendor was contacted early
about this disclosure but did not respond in any way.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3432</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2296</p>
</td>
<td rowspan="1" colspan="1">
<p>The Photo Gallery by 10Web – Mobile-Friendly Image Gallery plugin for
WordPress is vulnerable to Stored Cross-Site Scripting via SVG file uploads
in all versions up to, and including, 1.8.21 due to insufficient input
sanitization and output escaping. This makes it possible for authenticated
attackers, with administrator-level access, to inject arbitrary web scripts
in pages that will execute whenever a user accesses an injected page. This
only affects multi-site installations and installations where unfiltered_html
has been disabled.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2296</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29745</p>
</td>
<td rowspan="1" colspan="1">
<p>there is a possible Information Disclosure due to uninitialized data.
This could lead to local information disclosure with no additional execution
privileges needed. User interaction is not needed for exploitation.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29745</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31211</p>
</td>
<td rowspan="1" colspan="1">
<p>WordPress is an open publishing platform for the Web. Unserialization
of instances of the <code>WP_HTML_Token</code> class allows for code execution
via its <code>__destruct()</code> magic method. This issue was fixed in WordPress
6.4.2 on December 6th, 2023. Versions prior to 6.4.0 are not affected.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31211</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3262</p>
</td>
<td rowspan="1" colspan="1">
<p>Information exposure vulnerability in RT software affecting version 4.4.1.
This vulnerability allows an attacker with local access to the device to
retrieve sensitive information about the application, such as vulnerability
tickets, because the application stores the information in the browser
cache, leading to information exposure despite session termination.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3262</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-20334</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability in the web-based management interface of Cisco TelePresence
Management Suite (TMS) could allow a low-privileged, remote attacker to
conduct a cross-site scripting (XSS) attack against a user of the interface.\r
<br>\r This vulnerability is due to insufficient input validation by the web-based
management interface. An attacker could exploit this vulnerability by inserting
malicious data in a specific data field in the interface. A successful
exploit could allow the attacker to execute arbitrary script code in the
context of the affected interface or access sensitive, browser-based information.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-20334</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-20332</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability in the web-based management interface of Cisco Identity
Services Engine (ISE) could allow an authenticated, remote attacker to
conduct a server-side request forgery (SSRF) attack through an affected
device.\r
<br>\r This vulnerability is due to improper input validation for specific
HTTP requests. An attacker could exploit this vulnerability by sending
a crafted HTTP request to an affected device. A successful exploit could
allow the attacker to send arbitrary network requests that are sourced
from the affected device. To successfully exploit this vulnerability, the
attacker would need valid Super Admin credentials.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-20332</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2786</p>
</td>
<td rowspan="1" colspan="1">
<p>The Happy Addons for Elementor plugin for WordPress is vulnerable to Stored
Cross-Site Scripting via several widgets in all versions up to, and including,
3.10.4 due to insufficient input sanitization and output escaping on the
title_tag attribute. This makes it possible for authenticated attackers,
with contributor-level access and above, to inject arbitrary web scripts
in pages that will execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2786</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1641</p>
</td>
<td rowspan="1" colspan="1">
<p>The Accordion plugin for WordPress is vulnerable to unauthorized access
of data and modification of data due to a missing capability check on the
'accordions_duplicate_post_as_draft' function in all versions up to, and
including, 2.2.96. This makes it possible for authenticated attackers,
with contributor access and above, to duplicate arbitrary posts, allowing
access to the contents of password-protected posts.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1641</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28190</p>
</td>
<td rowspan="1" colspan="1">
<p>Contao is an open source content management system. Starting in version
4.0.0 and prior to version 4.13.40 and 5.3.4, users can inject malicious
code in filenames when uploading files (back end and front end), which
is then executed in tooltips and popups in the back end. Contao versions
4.13.40 and 5.3.4 have a patch for this issue. As a workaround, remove
upload fields from frontend forms and disable uploads for untrusted back
end users.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28190</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31369</p>
</td>
<td rowspan="1" colspan="1">
<p>Cross-Site Request Forgery (CSRF) vulnerability in PenciDesign Soledad.This
issue affects Soledad: from n/a through 8.4.2.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>5.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31369</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31375</p>
</td>
<td rowspan="1" colspan="1">
<p>Missing Authorization vulnerability in <a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">Saleswonder.Biz</a> Team WP2LEADS.This issue
affects WP2LEADS: from n/a through 3.2.7.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>5.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31375</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-23191</p>
</td>
<td rowspan="1" colspan="1">
<p>Upsell advertisement information of an account can be manipulated to execute
script code in the context of the users browser session. To exploit this
an attacker would require temporary access to a users account or an successful
social engineering attack to lure users to maliciously configured accounts.
Attackers could perform malicious API requests or extract information from
the users account. Please deploy the provided updates and patch releases.
Sanitization of user-defined upsell content has been improved. No publicly
available exploits are known.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-23191</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-23190</p>
</td>
<td rowspan="1" colspan="1">
<p>Upsell shop information of an account can be manipulated to execute script
code in the context of the users browser session. To exploit this an attacker
would require temporary access to a users account or an successful social
engineering attack to lure users to maliciously configured accounts. Attackers
could perform malicious API requests or extract information from the users
account. Please deploy the provided updates and patch releases. Sanitization
of user-defined upsell content has been improved. No publicly available
exploits are known.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-23190</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-23189</p>
</td>
<td rowspan="1" colspan="1">
<p>Embedded content references at tasks could be used to temporarily execute
script code in the context of the users browser session. To exploit this
an attacker would require temporary access to the users account, access
to another account within the same context or an successful social engineering
attack to make users import external content. Attackers could perform malicious
API requests or extract information from the users account. Please deploy
the provided updates and patch releases. Sanitization of user-generated
content has been improved. No publicly available exploits are known.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-23189</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3434</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability classified as critical was found in CP Plus Wi-Fi Camera
up to 20240401. Affected by this vulnerability is an unknown functionality
of the component User Management. The manipulation leads to improper authorization.
The attack can be launched remotely. The exploit has been disclosed to
the public and may be used. The associated identifier of this vulnerability
is VDB-259615. NOTE: The vendor was contacted early about this disclosure
but did not respond in any way.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3434</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-25705</p>
</td>
<td rowspan="1" colspan="1">
<p>There is a cross site scripting vulnerability in the Esri Portal for ArcGIS
Experience Builder 11.1 and below on Windows and Linux that allows a remote,
unauthenticated attacker to create a crafted link which when clicked could
potentially execute arbitrary JavaScript code in the victim’s browser.
The privileges required to execute this attack are low.&nbsp;</p>
</td>
<td rowspan="1" colspan="1">
<p>5.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-25705</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-25697</p>
</td>
<td rowspan="1" colspan="1">
<p>
<br>There is a Cross-site Scripting vulnerability&nbsp;in Portal for ArcGIS
in versions &lt;=11.1 that may allow a remote, authenticated attacker to
create a crafted link which when opening an authenticated users bio page
will render an image in the victims browser. &nbsp;The privileges required
to execute this attack are low.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>5.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-25697</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-25692</p>
</td>
<td rowspan="1" colspan="1">
<p>
<br>There is a cross-site-request forgery vulnerability in Esri Portal for
ArcGIS Versions 11.1 and below that may in some cases allow a remote, unauthenticated
attacker to trick an authorized user into executing unwanted actions via
a crafted form. The impact to Confidentiality and Integrity vectors is
limited and of low severity.&nbsp;</p>
</td>
<td rowspan="1" colspan="1">
<p>5.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-25692</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-20800</p>
</td>
<td rowspan="1" colspan="1">
<p>Adobe Experience Manager versions 6.5.19 and earlier are affected by a
DOM-based Cross-Site Scripting (XSS) vulnerability that could be abused
by a low-privileged attacker to inject malicious scripts into vulnerable
web pages. Malicious JavaScript may be executed in a victim’s browser when
they browse to the page containing the vulnerable script. This could result
in arbitrary code execution within the context of the victim's browser.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-20800</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-20367</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability in the web UI of Cisco Enterprise Chat and Email (ECE)
could allow an authenticated, remote attacker to conduct a cross-site scripting
(XSS) attack against a user of the interface.\r
<br>\r This vulnerability exists because the web UI does not properly validate
user-supplied input. An attacker could exploit this vulnerability by persuading
a user of the interface to click a crafted link. A successful exploit could
allow the attacker to execute arbitrary script code in the context of the
affected interface or access sensitive, browser-based information. To successfully
exploit this vulnerability, an attacker would need valid agent credentials.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-20367</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-20302</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability in the tenant security implementation of Cisco Nexus Dashboard
Orchestrator (NDO) could allow an authenticated, remote attacker to modify
or delete tenant templates on an affected system. \r
<br>\r
<br>This vulnerability is due to improper access controls within tenant security.
An attacker who is using a valid user account with write privileges and
either a Site Manager or Tenant Manager role could exploit this vulnerability.
A successful exploit could allow the attacker to modify or delete tenant
templates under non-associated tenants, which could disrupt network traffic.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-20302</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3218</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability classified as critical has been found in Shibang Communications
IP Network Intercom Broadcasting System 1.0. This affects an unknown part
of the file /php/busyscreenshotpush.php. The manipulation of the argument
jsondata[callee]/jsondata[imagename] leads to path traversal: '../filedir'.
It is possible to initiate the attack remotely. The exploit has been disclosed
to the public and may be used. The identifier VDB-259065 was assigned to
this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3218</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3213</p>
</td>
<td rowspan="1" colspan="1">
<p>The Relevanssi – A Better Search plugin for WordPress is vulnerable to
unauthorized modification of data due to a missing capability check on
the relevanssi_update_counts() function in all versions up to, and including,
4.22.1. This makes it possible for unauthenticated attackers to execute
expensive queries on the application that could lead into DOS.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3213</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3097</p>
</td>
<td rowspan="1" colspan="1">
<p>The WordPress Gallery Plugin – NextGEN Gallery plugin for WordPress is
vulnerable to unauthorized access of data due to a missing capability check
on the get_item function in versions up to, and including, 3.59. This makes
it possible for unauthenticated attackers to extract sensitive data including
EXIF and other metadata of any image uploaded through the plugin.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3097</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2974</p>
</td>
<td rowspan="1" colspan="1">
<p>The Essential Addons for Elementor – Best Elementor Templates, Widgets,
Kits &amp; WooCommerce Builders plugin for WordPress is vulnerable to Sensitive
Information Exposure in versions up to, and including, 5.9.13 via the load_more
function. This can allow unauthenticated attackers to extract sensitive
data including private and draft posts.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2974</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2340</p>
</td>
<td rowspan="1" colspan="1">
<p>The Avada theme for WordPress is vulnerable to Sensitive Information Exposure
in all versions up to, and including, 7.11.6 via the '/wp-content/uploads/fusion-forms/'
directory. This makes it possible for unauthenticated attackers to extract
sensitive data uploaded via an Avada created form with a file upload mechanism.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2340</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2302</p>
</td>
<td rowspan="1" colspan="1">
<p>The Easy Digital Downloads – Sell Digital Files &amp; Subscriptions (eCommerce
Store + Payments Made Easy) plugin for WordPress is vulnerable to Sensitive
Information Exposure in all versions up to, and including, 3.2.9. This
makes it possible for unauthenticated attackers to download the debug log
via Directory Listing. This file may include PII.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2302</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1984</p>
</td>
<td rowspan="1" colspan="1">
<p>The Graphene theme for WordPress is vulnerable to unauthorized access
of data via meta tag in all versions up to, and including, 2.9.2. This
makes it possible for unauthenticated individuals to obtain post contents
of password protected posts via the generated source.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1984</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1587</p>
</td>
<td rowspan="1" colspan="1">
<p>The Newsmatic theme for WordPress is vulnerable to Sensitive Information
Exposure in all versions up to, and including, 1.3.0 via the 'newsmatic_filter_posts_load_tab_content'.
This makes it possible for unauthenticated attackers to view draft posts
and post content.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1587</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-0899</p>
</td>
<td rowspan="1" colspan="1">
<p>The s2Member – Best Membership Plugin for All Kinds of Memberships, Content
Restriction Paywalls &amp; Member Access Subscriptions plugin for WordPress
is vulnerable to Information Exposure in all versions up to, and including,
230815 via the API. This makes it possible for unauthenticated attackers
to see the contents of those posts and pages.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-0899</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-0626</p>
</td>
<td rowspan="1" colspan="1">
<p>The WooCommerce Clover Payment Gateway plugin for WordPress is vulnerable
to unauthorized modification of data due to a missing capability check
on the callback_handler function in all versions up to, and including,
1.3.1. This makes it possible for unauthenticated attackers to mark orders
as paid.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-0626</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-6777</p>
</td>
<td rowspan="1" colspan="1">
<p>The WP Go Maps (formerly WP Google Maps) plugin for WordPress is vulnerable
to unauthenticated API key disclosure in versions up to, and including,
9.0.34 due to the plugin adding the API key to several plugin files. This
makes it possible for unauthenticated attackers to obtain the developer's
Google API key. While this does not affect the security of sites using
this plugin, it allows unauthenticated attackers to make requests using
this API key with the potential of exhausting requests resulting in an
inability to use the map functionality offered by the plugin.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-6777</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-23662</p>
</td>
<td rowspan="1" colspan="1">
<p>An exposure of sensitive information to an unauthorized actor in Fortinet
FortiOS at least version at least 7.4.0 through 7.4.1 and 7.2.0 through
7.2.5 and 7.0.0 through 7.0.15 and 6.4.0 through 6.4.15 allows attacker
to information disclosure via HTTP requests.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-23662</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27898</p>
</td>
<td rowspan="1" colspan="1">
<p>SAP NetWeaver application, due to insufficient input validation, allows
an attacker to send a crafted request from a vulnerable web application
targeting internal systems behind firewalls that are normally inaccessible
to an attacker from the external network, resulting in a&nbsp;Server-Side
Request Forgery vulnerability. Thus, having a low impact on confidentiality.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27898</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31447</p>
</td>
<td rowspan="1" colspan="1">
<p>Shopware 6 is an open commerce platform based on Symfony Framework and
Vue. Starting in version 6.3.5.0 and prior to versions 6.6.1.0 and 6.5.8.8,
when a authenticated request is made to <code>POST /store-api/account/logout</code>,
the cart will be cleared, but the User won't be logged out. This affects
only the direct store-api usage, as the PHP Storefront listens additionally
on <code>CustomerLogoutEvent</code> and invalidates the session additionally.
The problem has been fixed in Shopware 6.6.1.0 and 6.5.8.8. Those who are
unable to update can install the latest version of the Shopware Security
Plugin as a workaround.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31447</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30269</p>
</td>
<td rowspan="1" colspan="1">
<p>DataEase, an open source data visualization and analysis tool, has a database
configuration information exposure vulnerability prior to version 2.5.0.
Visiting the <code>/de2api/engine/getEngine;.js</code> path via a browser
reveals that the platform's database configuration is returned. The vulnerability
has been fixed in v2.5.0. No known workarounds are available aside from
upgrading.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30269</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2021-4438</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability, which was classified as critical, has been found in kyivstarteam
react-native-sms-user-consent up to 1.1.4 on Android. Affected by this
issue is the function registerReceiver of the file android/src/main/java/ua/kyivstar/reactnativesmsuserconsent/SmsUserConsentModule.kt.
The manipulation leads to improper export of android application components.
Attacking locally is a requirement. Upgrading to version 1.1.5 is able
to address this issue. The name of the patch is 5423dcb0cd3e4d573b5520a71fa08aa279e4c3c7.
It is recommended to upgrade the affected component. The identifier of
this vulnerability is VDB-259508.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2021-4438</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3216</p>
</td>
<td rowspan="1" colspan="1">
<p>The WooCommerce PDF Invoices, Packing Slips, Delivery Notes and Shipping
Labels plugin for WordPress is vulnerable to unauthorized modification
of data due to a missing capability check on the wt_pklist_reset_settings()
function in all versions up to, and including, 4.4.2. This makes it possible
for unauthenticated attackers to reset all of the plugin's settings.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3216</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2950</p>
</td>
<td rowspan="1" colspan="1">
<p>The BoldGrid Easy SEO – Simple and Effective SEO plugin for WordPress
is vulnerable to Information Exposure in all versions up to, and including,
1.6.14 via meta information (og:description) This makes it possible for
unauthenticated attackers to view the first 130 characters of a password
protected post which can contain sensitive information.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2950</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27910</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was reported in some Lenovo Printers that could allow
an unauthenticated attacker to reboot the printer without authentication.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27910</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-5692</p>
</td>
<td rowspan="1" colspan="1">
<p>WordPress Core is vulnerable to Sensitive Information Exposure in versions
up to, and including, 6.4.3 via the redirect_guess_404_permalink function.
This can allow unauthenticated attackers to expose the slug of a custom
post whose 'publicly_queryable' post status has been set to 'false'.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-5692</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30255</p>
</td>
<td rowspan="1" colspan="1">
<p>Envoy is a cloud-native, open source edge and service proxy. The HTTP/2
protocol stack in Envoy versions prior to 1.29.3, 1.28.2, 1.27.4, and 1.26.8
are vulnerable to CPU exhaustion due to flood of CONTINUATION frames. Envoy's
HTTP/2 codec allows the client to send an unlimited number of CONTINUATION
frames even after exceeding Envoy's header map limits. This allows an attacker
to send a sequence of CONTINUATION frames without the END_HEADERS bit set
causing CPU utilization, consuming approximately 1 core per 300Mbit/s of
traffic and culminating in denial of service through CPU exhaustion. Users
should upgrade to version 1.29.3, 1.28.2, 1.27.4, or 1.26.8 to mitigate
the effects of the CONTINUATION flood. As a workaround, disable HTTP/2
protocol for downstream connections.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30255</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-22023</p>
</td>
<td rowspan="1" colspan="1">
<p>An XML entity expansion or XEE vulnerability in SAML component of Ivanti
Connect Secure (9.x, 22.x) and Ivanti Policy Secure allows an unauthenticated
attacker to send specially crafted XML requests in-order-to temporarily
cause resource exhaustion thereby resulting in a limited-time DoS.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-22023</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31209</p>
</td>
<td rowspan="1" colspan="1">
<p>oidcc is the OpenID Connect client library for Erlang. Denial of Service
(DoS) by Atom exhaustion is possible by calling <code>oidcc_provider_configuration_worker:get_provider_configuration/1</code> or <code>oidcc_provider_configuration_worker:get_jwks/1</code>.
This issue has been patched in version(s)`3.1.2` &amp; <code>3.2.0-beta.3</code>.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31209</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28182</p>
</td>
<td rowspan="1" colspan="1">
<p>nghttp2 is an implementation of the Hypertext Transfer Protocol version
2 in C. The nghttp2 library prior to version 1.61.0 keeps reading the unbounded
number of HTTP/2 CONTINUATION frames even after a stream is reset to keep
HPACK context in sync. This causes excessive CPU usage to decode HPACK
stream. nghttp2 v1.61.0 mitigates this vulnerability by limiting the number
of CONTINUATION frames it accepts per stream. There is no workaround for
this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28182</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1418</p>
</td>
<td rowspan="1" colspan="1">
<p>The CGC Maintenance Mode plugin for WordPress is vulnerable to Sensitive
Information Exposure in all versions up to, and including, 1.2 via the
REST API. This makes it possible for unauthenticated attackers to view
protected posts via REST API even when maintenance mode is enabled.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1418</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-23540</p>
</td>
<td rowspan="1" colspan="1">
<p>The HCL BigFix Inventory server is vulnerable to path traversal which
enables an attacker to read internal application files from the Inventory
server. The BigFix Inventory server does not properly restrict the served
static file.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-23540</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-35812</p>
</td>
<td rowspan="1" colspan="1">
<p>An issue was discovered in the Amazon Linux packages of OpenSSH 7.4 for
Amazon Linux 1 and 2, because of an incomplete fix for CVE-2019-6111 within
these specific packages. The fix had only covered cases where an absolute
path is passed to scp. When a relative path is used, there is no verification
that the name of a file received by the client matches the file requested.
Fixed packages are available with numbers 7.4p1-22.78.amzn1 and 7.4p1-22.amzn2.0.2.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-35812</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27254</p>
</td>
<td rowspan="1" colspan="1">
<p>IBM Db2 for Linux, UNIX and Windows (includes DB2 Connect Server) 10.5,
11.1, and 11.5 federated server is vulnerable to denial of service with
a specially crafted query under certain conditions. IBM X-Force ID: 283813.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27254</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-25046</p>
</td>
<td rowspan="1" colspan="1">
<p>IBM Db2 for Linux, UNIX and Windows (includes Db2 Connect Server) 11.1
and 11.5 is vulnerable to a denial of service by an authenticated user
using a specially crafted query. IBM X-Force ID: 282953.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-25046</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-22360</p>
</td>
<td rowspan="1" colspan="1">
<p>IBM Db2 for Linux, UNIX and Windows (includes Db2 Connect Server) 11.5
is vulnerable to a denial of service with a specially crafted query on
certain columnar tables. IBM X-Force ID: 280905.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-22360</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52296</p>
</td>
<td rowspan="1" colspan="1">
<p>IBM DB2 for Linux, UNIX and Windows (includes Db2 Connect Server) 11.5
is vulnerable to denial of service when querying a specific UDF built-in
function concurrently. IBM X-Force ID: 278547.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52296</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-21506</p>
</td>
<td rowspan="1" colspan="1">
<p>Versions of the package pymongo before 4.6.3 are vulnerable to Out-of-bounds
Read in the bson module. Using the crafted payload the attacker could force
the parser to deserialize unmanaged memory. The parser tries to interpret
bytes next to buffer and throws an exception with string. If the following
bytes are not printable UTF-8 the parser throws an exception with a single
byte.</p>
</td>
<td rowspan="1" colspan="1">
<p>5.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-21506</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26220</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Mobile Hotspot Information Disclosure Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26220</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1790</p>
</td>
<td rowspan="1" colspan="1">
<p>The WordPress Infinite Scroll – Ajax Load More plugin for WordPress is
vulnerable to Path Traversal in all versions up to, and including, 7.0.1
via the 'type' parameter. This makes it possible for authenticated attackers,
with administrator-level access and above, to read the contents of arbitrary
files on the server, which can contain sensitive information. This is limited
to Windows instances.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1790</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27909</p>
</td>
<td rowspan="1" colspan="1">
<p>A denial of service vulnerability was reported in the HTTPS service of
some Lenovo Printers that could result in a system reboot.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27909</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27908</p>
</td>
<td rowspan="1" colspan="1">
<p>A buffer overflow vulnerability was reported in the HTTPS service of some
Lenovo Printers that could result in denial of service.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27908</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-20352</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability in Cisco Emergency Responder could allow an authenticated,
remote attacker to conduct a directory traversal attack, which could allow
the attacker to perform arbitrary actions on an affected device. This vulnerability
is due to insufficient protections for the web UI of an affected system.
An attacker could exploit this vulnerability by sending crafted requests
to the web UI. A successful exploit could allow the attacker to perform
arbitrary actions with the privilege level of the affected user, such as
accessing password or log files or uploading and deleting existing files
from the system.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-20352</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27201</p>
</td>
<td rowspan="1" colspan="1">
<p>An improper input validation vulnerability exists in the OAS Engine User
Configuration functionality of Open Automation Software OAS Platform V19.00.0057.
A specially crafted series of network requests can lead to unexpected data
in the configuration. An attacker can send a sequence of requests to trigger
this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27201</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-24976</p>
</td>
<td rowspan="1" colspan="1">
<p>A denial of service vulnerability exists in the OAS Engine File Data Source
Configuration functionality of Open Automation Software OAS Platform V19.00.0057.
A specially crafted series of network requests can cause the running program
to stop. An attacker can send a sequence of requests to trigger this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-24976</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-22178</p>
</td>
<td rowspan="1" colspan="1">
<p>A file write vulnerability exists in the OAS Engine Save Security Configuration
functionality of Open Automation Software OAS Platform V19.00.0057. A specially
crafted series of network requests can lead to arbitrary file creation
or overwrite. An attacker can send a sequence of requests to trigger this
vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-22178</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-21870</p>
</td>
<td rowspan="1" colspan="1">
<p>A file write vulnerability exists in the OAS Engine Tags Configuration
functionality of Open Automation Software OAS Platform V19.00.0057. A specially
crafted series of network requests can lead to arbitrary file creation
or overwrite. An attacker can send a sequence of requests to trigger this
vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-21870</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30215</p>
</td>
<td rowspan="1" colspan="1">
<p>The Resource Settings page allows a high privilege attacker to load exploitable
payload to be stored and reflected whenever a User visits the page. In
a successful attack, some information could be obtained and/or modified.
However,&nbsp;the attacker does not have control over what information
is obtained, or the amount or kind of loss is limited.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>4.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30215</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30214</p>
</td>
<td rowspan="1" colspan="1">
<p>The application allows a high privilege attacker to append a malicious
GET query parameter to Service invocations, which are reflected in the
server response. Under certain circumstances, if the parameter contains
a JavaScript, the script could be processed on client side.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>4.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30214</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-25708</p>
</td>
<td rowspan="1" colspan="1">
<p>There is a stored Cross-site Scripting vulnerability in Esri Portal for
ArcGIS Enterprise Web App Builder versions 10.8.1 – 10.9.1 that may allow
a remote, authenticated attacker to create a crafted link which when clicked
could potentially execute arbitrary JavaScript code in the victim’s browser.
The privileges required to execute this attack are high.&nbsp;</p>
</td>
<td rowspan="1" colspan="1">
<p>4.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-25708</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-25704</p>
</td>
<td rowspan="1" colspan="1">
<p>There is a stored Cross-site Scripting vulnerability in Esri Portal for
ArcGIS Enterprise Experience Builder versions &lt;= 11.1 that may allow
a remote, authenticated attacker to create a crafted link that is stored
in the Experience Builder Embed widget which when loaded could potentially
execute arbitrary JavaScript code in the victim’s browser. The privileges
required to execute this attack are high.&nbsp;</p>
</td>
<td rowspan="1" colspan="1">
<p>4.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-25704</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-25700</p>
</td>
<td rowspan="1" colspan="1">
<p>There is a stored Cross-site Scripting vulnerability in Esri Portal for
ArcGIS Enterprise Web App Builder versions &lt;= 11.1 that may allow a
remote, authenticated attacker to create a crafted link that is stored
in a web map link which when clicked could potentially execute arbitrary
JavaScript code in the victim’s browser. The privileges required to execute
this attack are high.&nbsp;</p>
</td>
<td rowspan="1" colspan="1">
<p>4.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-25700</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-25696</p>
</td>
<td rowspan="1" colspan="1">
<p>There is a Cross-site Scripting vulnerability in Portal for ArcGIS in
versions &lt;=11.0 that may allow a remote, authenticated attacker to create
a crafted link which when accessing the page editor an image will render
in the victim’s browser. The privileges required to execute this attack
are high.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-25696</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3521</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in Byzoro Smart S80 Management Platform up to
20240317. It has been rated as critical. Affected by this issue is some
unknown functionality of the file /useratte/userattestation.php. The manipulation
of the argument web_img leads to unrestricted upload. The attack may be
launched remotely. The exploit has been disclosed to the public and may
be used. The identifier of this vulnerability is VDB-259892. NOTE: The
vendor was contacted early about this disclosure but did not respond in
any way.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3521</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3444</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in Wangshen SecGate 3600 up to 20240408. It
has been classified as critical. This affects an unknown part of the file
/?g=net_pro_keyword_import_save. The manipulation of the argument reqfile
leads to unrestricted upload. It is possible to initiate the attack remotely.
The exploit has been disclosed to the public and may be used. The identifier
VDB-259701 was assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3444</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3440</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Prison Management System 1.0.
It has been declared as critical. Affected by this vulnerability is an
unknown functionality of the file /Admin/edit_profile.php. The manipulation
leads to sql injection. The attack can be launched remotely. The exploit
has been disclosed to the public and may be used. The identifier VDB-259693
was assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3440</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3437</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Prison Management System 1.0.
It has been rated as critical. This issue affects some unknown processing
of the file /Admin/add-admin.php of the component Avatar Handler. The manipulation
of the argument avatar leads to unrestricted upload. The attack may be
initiated remotely. The exploit has been disclosed to the public and may
be used. The associated identifier of this vulnerability is VDB-259631.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3437</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3431</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in EyouCMS 1.6.5. It has been declared as critical.
This vulnerability affects unknown code of the file /login.php?m=admin&amp;c=Field&amp;a=channel_edit
of the component Backend. The manipulation of the argument channel_id leads
to deserialization. The attack can be initiated remotely. The exploit has
been disclosed to the public and may be used. The identifier of this vulnerability
is VDB-259612. NOTE: The vendor was contacted early about this disclosure
but did not respond in any way.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3431</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29221</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Access Control in Mattermost Server versions 9.5.x before 9.5.2,
9.4.x before 9.4.4, 9.3.x before 9.3.3, 8.1.x before 8.1.11 lacked proper
access control in the <code>/api/v4/users/me/teams</code> endpoint&nbsp;allowing&nbsp;a
team admin to get the invite ID of their team, thus allowing them to invite
users, even if the "Add Members" permission was explicitly removed from
team admins.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>4.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29221</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-25690</p>
</td>
<td rowspan="1" colspan="1">
<p>There is an HTML injection vulnerability in Esri Portal for ArcGIS versions
11.1 and below that may allow a remote, unauthenticated attacker to create
a crafted link which when clicked could render arbitrary HTML in the victim’s
browser.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-25690</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3227</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in Panwei eoffice OA up to 9.5. It has been
declared as critical. This vulnerability affects unknown code of the file
/general/system/interface/theme_set/save_image.php of the component Backend.
The manipulation of the argument image_type leads to path traversal: '../filedir'.
The attack can be initiated remotely. The exploit has been disclosed to
the public and may be used. The identifier of this vulnerability is VDB-259072.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.7</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3227</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2380</p>
</td>
<td rowspan="1" colspan="1">
<p>Stored XSS in graph rendering in Checkmk &lt;2.3.0b4.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.6</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2380</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3093</p>
</td>
<td rowspan="1" colspan="1">
<p>The Font Farsi plugin for WordPress is vulnerable to Stored Cross-Site
Scripting via admin settings in all versions up to, and including 1.6.6
due to insufficient input sanitization and output escaping. This makes
it possible for authenticated attackers, with administrator-level permissions
and above, to inject arbitrary web scripts in pages that will execute whenever
a user accesses an injected page. This only affects multi-site installations
and installations where unfiltered_html has been disabled.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3093</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1571</p>
</td>
<td rowspan="1" colspan="1">
<p>The WP Recipe Maker plugin for WordPress is vulnerable to Stored Cross-Site
Scripting via the Video Embed parameter in all versions up to, and including,
9.2.1 due to insufficient input sanitization and output escaping. This
makes it possible for authenticated attackers, with access to the recipe
dashboard (which is administrator-only by default but can be assigned to
arbitrary capabilities), to inject arbitrary web scripts in pages that
will execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1571</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1463</p>
</td>
<td rowspan="1" colspan="1">
<p>The LearnPress – WordPress LMS Plugin plugin for WordPress is vulnerable
to Stored Cross-Site Scripting via the Course, Lesson, and Quiz title and
content in all versions up to, and including, 4.2.6.3 due to insufficient
input sanitization and output escaping. This makes it possible for authenticated
attackers, with LP Instructor-level access, to inject arbitrary web scripts
in pages that will execute whenever a user accesses an injected page.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1463</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-0662</p>
</td>
<td rowspan="1" colspan="1">
<p>The FancyBox for WordPress plugin for WordPress is vulnerable to Stored
Cross-Site Scripting via admin settings in versions 3.0.2 to 3.3.3 due
to insufficient input sanitization and output escaping. This makes it possible
for authenticated attackers, with administrator-level permissions and above,
to inject arbitrary web scripts in pages that will execute whenever a user
accesses an injected page. This only affects multi-site installations and
installations where unfiltered_html has been disabled.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-0662</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-0598</p>
</td>
<td rowspan="1" colspan="1">
<p>The Gutenberg Blocks by Kadence Blocks – Page Builder Features plugin
for WordPress is vulnerable to Stored Cross-Site Scripting via the contact
form message settings in all versions up to and including 3.2.17 due to
insufficient input sanitization and output escaping. This makes it possible
for authenticated attackers, with editor-level access and above, to inject
arbitrary web scripts in pages that will execute whenever a user accesses
an injected page. This primarily affects multi-site installations and installations
where unfiltered_html has been disabled.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-0598</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31308</p>
</td>
<td rowspan="1" colspan="1">
<p>Deserialization of Untrusted Data vulnerability in VJInfotech WP Import
Export Lite.This issue affects WP Import Export Lite: from n/a through
3.9.26.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>4.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31308</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2656</p>
</td>
<td rowspan="1" colspan="1">
<p>The Email Subscribers by Icegram Express – Email Marketing, Newsletters,
Automation for WordPress &amp; WooCommerce plugin for WordPress is vulnerable
to Stored Cross-Site Scripting via a CSV import in all versions up to,
and including, 5.7.14 due to insufficient input sanitization and output
escaping. This makes it possible for authenticated attackers, with administrator-level
permissions and above, to inject arbitrary web scripts in pages that will
execute whenever a user accesses an injected page. This only affects multi-site
installations and installations where unfiltered_html has been disabled.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2656</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3030</p>
</td>
<td rowspan="1" colspan="1">
<p>The Announce from the Dashboard plugin for WordPress is vulnerable to
Stored Cross-Site Scripting via admin settings in all versions up to, and
including, 1.5.2 due to insufficient input sanitization and output escaping.
This makes it possible for authenticated attackers, with administrator-level
permissions and above, to inject arbitrary web scripts in pages that will
execute whenever a user accesses an injected page. This only affects multi-site
installations and installations where unfiltered_html has been disabled.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3030</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2689</p>
</td>
<td rowspan="1" colspan="1">
<p>Denial of Service in Temporal Server prior to version 1.20.5, 1.21.6,
and 1.22.7 allows an authenticated user who has permissions to interact
with workflows and has crafted an invalid UTF-8 string for submission to
potentially cause a crashloop. If left unchecked, the task containing the
invalid UTF-8 will become stuck in the queue, causing an increase in queue
lag. Eventually, all processes handling these queues will become stuck
and the system will run out of resources. The workflow ID of the failing
task will be visible in the logs, and can be used to remove that workflow
as a mitigation. Version 1.23 is not impacted.&nbsp;In this context, a
user is an operator of Temporal Server.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2689</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2543</p>
</td>
<td rowspan="1" colspan="1">
<p>The Permalink Manager Lite plugin for WordPress is vulnerable to unauthorized
access of data due to a missing capability check on the 'get_uri_editor'
function in all versions up to, and including, 2.4.3.1. This makes it possible
for unauthenticated attackers to view the permalinks of all posts.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2543</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2261</p>
</td>
<td rowspan="1" colspan="1">
<p>The Event Tickets and Registration plugin for WordPress is vulnerable
to Sensitive Information Exposure in all versions up to, and including,
5.8.2 via the RSVP functionality. This makes it possible for authenticated
attackers, with contributor access and above, to extract sensitive data
including emails and street addresses.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2261</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2222</p>
</td>
<td rowspan="1" colspan="1">
<p>The Advanced Classifieds &amp; Directory Pro plugin for WordPress is vulnerable
to unauthorized loss of data due to a missing capability check on the ajax_callback_delete_attachment
function in all versions up to, and including, 3.0.0. This makes it possible
for authenticated attackers, with subscriber access or higher, to delete
arbitrary media uploads.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2222</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2033</p>
</td>
<td rowspan="1" colspan="1">
<p>The Video Conferencing with Zoom plugin for WordPress is vulnerable to
Sensitive Information Exposure in all versions up to, and including, 4.4.5
via the get_assign_host_id AJAX action. This makes it possible for authenticated
attackers, with subscriber access or higher, to enumerate usernames, emails
and IDs of all users on a site.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2033</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1904</p>
</td>
<td rowspan="1" colspan="1">
<p>The MasterStudy LMS plugin for WordPress is vulnerable to unauthorized
access of data due to a missing capability check on the search_posts function
in all versions up to, and including, 3.2.13. This makes it possible for
authenticated attackers, with subscriber-level access and above, to expose
draft post titles and excerpts.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1904</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1637</p>
</td>
<td rowspan="1" colspan="1">
<p>The 360 Javascript Viewer plugin for WordPress is vulnerable to unauthorized
modification of data due to a missing capability check and nonce exposure
on several AJAX actions in all versions up to, and including, 1.7.12. This
makes it possible for authenticated attackers, with subscriber access or
higher, to update plugin settings.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1637</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1387</p>
</td>
<td rowspan="1" colspan="1">
<p>The Happy Addons for Elementor plugin for WordPress is vulnerable to unauthorized
access of data due to insufficient authorization on the duplicate_thing()
function in all versions up to, and including, 3.10.4. This makes it possible
for attackers, with contributor-level access and above, to clone arbitrary
posts (including private and password protected ones) which may lead to
information exposure.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1387</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-0872</p>
</td>
<td rowspan="1" colspan="1">
<p>The Watu Quiz plugin for WordPress is vulnerable to Sensitive Information
Exposure in all versions up to, and including, 3.4.1 via the watu-userinfo
shortcode. This makes it possible for authenticated attackers, with contributor-level
access and above, to extract sensitive user meta data which can include
session tokens and user emails.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-0872</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-0588</p>
</td>
<td rowspan="1" colspan="1">
<p>The Paid Memberships Pro – Content Restriction, User Registration, &amp;
Paid Subscriptions plugin for WordPress is vulnerable to Cross-Site Request
Forgery in all versions up to, and including, 2.12.10. This is due to missing
nonce validation on the pmpro_lifter_save_streamline_option() function.
This makes it possible for unauthenticated attackers to enable the streamline
setting with Lifter LMS via a forged request granted they can trick a site
administrator into performing an action such as clicking on a link.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-0588</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-6965</p>
</td>
<td rowspan="1" colspan="1">
<p>The Pods – Custom Content Types and Fields plugin for WordPress is vulnerable
to Missing Authorization in all versions up to, and including, 3.0.10 (with
the exception of 2.7.31.2, 2.8.23.2, 2.9.19.2). This is due to the fact
that the plugin allows the use of a file inclusion feature via shortcode.
This makes it possible for authenticated attackers, with contributor access
or higher, to create pods and users (with default role).</p>
</td>
<td rowspan="1" colspan="1">
<p>4.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-6965</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31455</p>
</td>
<td rowspan="1" colspan="1">
<p>Minder by Stacklok is an open source software supply chain security platform.
A refactoring in commit <code>5c381cf</code> added the ability to get GitHub
repositories registered to a project without specifying a specific provider.
Unfortunately, the SQL query for doing so was missing parenthesis, and
would select a random repository. This issue is patched in pull request
2941. As a workaround, revert prior to <code>5c381cf</code>, or roll forward
past <code>2eb94e7</code>.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31455</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29056</p>
</td>
<td rowspan="1" colspan="1">
<p>Windows Authentication Elevation of Privilege Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>4.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29056</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28234</p>
</td>
<td rowspan="1" colspan="1">
<p>Contao is an open source content management system. Starting in version
2.0.0 and prior to versions 4.13.40 and 5.3.4, it is possible to inject
CSS styles via BBCode in comments. Installations are only affected if BBCode
is enabled. Contao versions 4.13.40 and 5.3.4 have a patch for this issue.
As a workaround, disable BBCode for comments.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28234</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30217</p>
</td>
<td rowspan="1" colspan="1">
<p>Cash Management in SAP S/4 HANA does not perform necessary authorization
checks for an authenticated user, resulting in escalation of privileges.
By exploiting this vulnerability, an attacker can approve or reject a bank
account application affecting the integrity of the application. Confidentiality
and Availability are not impacted.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>4.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30217</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30216</p>
</td>
<td rowspan="1" colspan="1">
<p>Cash Management in SAP S/4 HANA does not perform necessary authorization
checks for an authenticated user, resulting in escalation of privileges.
By&nbsp;exploiting this vulnerability, attacker can add notes in the review
request with 'completed' status affecting the integrity of the application.&nbsp;Confidentiality
and Availability are not impacted.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>4.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30216</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31296</p>
</td>
<td rowspan="1" colspan="1">
<p>Authorization Bypass Through User-Controlled Key vulnerability in Repute
Infosystems BookingPress.This issue affects BookingPress: from n/a through
1.0.81.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>4.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31296</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31291</p>
</td>
<td rowspan="1" colspan="1">
<p>Authorization Bypass Through User-Controlled Key vulnerability in Metagauss
ProfileGrid.This issue affects ProfileGrid : from n/a through 5.7.6.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>4.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31291</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-22155</p>
</td>
<td rowspan="1" colspan="1">
<p>Cross-Site Request Forgery (CSRF) vulnerability in Automattic WooCommerce.This
issue affects WooCommerce: from n/a through 8.5.2.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>4.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-22155</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3378</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability has been found in iboss Secure Web Gateway up to 10.1
and classified as problematic. Affected by this vulnerability is an unknown
functionality of the file /login of the component Login Portal. The manipulation
of the argument redirectUrl leads to cross site scripting. The attack can
be launched remotely. The exploit has been disclosed to the public and
may be used. Upgrading to version 10.2.0.160 is able to address this issue.
It is recommended to upgrade the affected component. The identifier VDB-259501
was assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3378</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3377</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability classified as problematic was found in SourceCodester
Computer Laboratory Management System 1.0. This vulnerability affects unknown
code of the file /classes/SystemSettings.php?f=update_settings. The manipulation
of the argument name leads to cross site scripting. The attack can be initiated
remotely. The exploit has been disclosed to the public and may be used.
VDB-259498 is the identifier assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3377</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1994</p>
</td>
<td rowspan="1" colspan="1">
<p>The Image Watermark plugin for WordPress is vulnerable to unauthorized
modification of data due to a missing capability check on the watermark_action_ajax()
function in all versions up to, and including, 1.7.3. This makes it possible
for authenticated attackers, with subscriber-level access and above, to
apply and remove watermarks from images.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1994</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28949</p>
</td>
<td rowspan="1" colspan="1">
<p>Mattermost Server versions 9.5.x before 9.5.2, 9.4.x before 9.4.4, 9.3.x
before 9.3.3, 8.1.x before 8.1.11 don't limit the number of user preferences
which allows an attacker to send a large number of user preferences potentially
causing denial of service.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>4.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28949</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-5973</p>
</td>
<td rowspan="1" colspan="1">
<p>Brocade
<br>Web Interface in Brocade Fabric OS v9.x and before v9.2.0 does not
<br>properly represent the portName to the user if the portName contains
<br>reserved characters. This could allow an authenticated user to alter the
<br>UI of the Brocade Switch and change ports display.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>4.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-5973</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29981</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft Edge (Chromium-based) Spoofing Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>4.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29981</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-20347</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability in Cisco Emergency Responder could allow an unauthenticated,
remote attacker to conduct a CSRF attack, which could allow the attacker
to perform arbitrary actions on an affected device. This vulnerability
is due to insufficient protections for the web UI of an affected system.
An attacker could exploit this vulnerability by persuading a user to click
a crafted link. A successful exploit could allow the attacker to perform
arbitrary actions with the privilege level of the affected user, such as
deleting users from the device.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-20347</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-20283</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability in Cisco Nexus Dashboard could allow an authenticated,
remote attacker to learn cluster deployment information on an affected
device.\r
<br>\r This vulnerability is due to improper access controls on a specific
API endpoint. An attacker could exploit this vulnerability by sending queries
to the API endpoint. A successful exploit could allow an attacker to access
metrics and information about devices in the Nexus Dashboard cluster.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-20283</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31419</p>
</td>
<td rowspan="1" colspan="1">
<p>An information disclosure flaw was found in OpenShift Virtualization.
The DownwardMetrics feature was introduced to expose host metrics to virtual
machine guests and is enabled by default. This issue could expose limited
host metrics of a node to any guest in any namespace without being explicitly
enabled by an administrator.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31419</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31205</p>
</td>
<td rowspan="1" colspan="1">
<p>Saleor is an e-commerce platform. Starting in version 3.10.0 and prior
to versions 3.14.64, 3.15.39, 3.16.39, 3.17.35, 3.18.31, and 3.19.19, an
attacker may bypass cross-set request forgery (CSRF) validation when calling
refresh token mutation with empty string. When a user provides an empty
string in <code>refreshToken</code> mutation, while the token persists in <code>JWT_REFRESH_TOKEN_COOKIE_NAME</code> cookie,
application omits validation against CSRF token and returns valid access
token. Versions 3.14.64, 3.15.39, 3.16.39, 3.17.35, 3.18.31, and 3.19.19
contain a patch for the issue. As a workaround, one may replace <code>saleor.graphql.account.mutations.authentication.refresh_token.py.get_refresh_token</code>.
This will fix the issue, but be aware, that it returns <code>JWT_MISSING_TOKEN</code> instead
of <code>JWT_INVALID_TOKEN</code>.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31205</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27242</p>
</td>
<td rowspan="1" colspan="1">
<p>Cross site scripting in Zoom Desktop Client for Linux before version 5.17.10
may allow an authenticated user to conduct a denial of service via network
access.</p>
</td>
<td rowspan="1" colspan="1">
<p>4.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27242</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28922</p>
</td>
<td rowspan="1" colspan="1">
<p>Secure Boot Security Feature Bypass Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>4.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28922</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29049</p>
</td>
<td rowspan="1" colspan="1">
<p>Microsoft Edge (Chromium-based) Webview2 Spoofing Vulnerability</p>
</td>
<td rowspan="1" colspan="1">
<p>4.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29049</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30260</p>
</td>
<td rowspan="1" colspan="1">
<p>Undici is an HTTP/1.1 client, written from scratch for Node.js. Undici
cleared Authorization and Proxy-Authorization headers for <code>fetch()</code>,
but did not clear them for <code>undici.request()</code>. This vulnerability
was patched in version(s) 5.28.4 and 6.11.1.</p>
</td>
<td rowspan="1" colspan="1">
<p>3.9</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30260</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3270</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability classified as problematic was found in ThingsBoard up
to 3.6.2. This vulnerability affects unknown code of the component AdvancedFeature.
The manipulation leads to improper access controls. The attack can be initiated
remotely. The exploit has been disclosed to the public and may be used.
VDB-259282 is the identifier assigned to this vulnerability. NOTE: The
vendor was contacted early about this disclosure and replied to be planning
to fix this issue in version 3.7.</p>
</td>
<td rowspan="1" colspan="1">
<p>3.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3270</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3463</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability has been found in SourceCodester Laundry Management System
1.0 and classified as problematic. This vulnerability affects unknown code
of the file /karyawan/edit. The manipulation of the argument karyawan leads
to cross site scripting. The attack can be initiated remotely. The exploit
has been disclosed to the public and may be used. The identifier of this
vulnerability is VDB-259744.</p>
</td>
<td rowspan="1" colspan="1">
<p>3.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3463</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3443</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability classified as problematic was found in SourceCodester
Prison Management System 1.0. This vulnerability affects unknown code of
the file /Employee/apply_leave.php. The manipulation of the argument txtstart_date/txtend_date
leads to cross site scripting. The attack can be initiated remotely. The
exploit has been disclosed to the public and may be used. The identifier
of this vulnerability is VDB-259696.</p>
</td>
<td rowspan="1" colspan="1">
<p>3.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3443</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2014-125111</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in namithjawahar Wp-Insert up to 2.0.8 and classified
as problematic. Affected by this issue is some unknown functionality. The
manipulation leads to cross site scripting. The attack may be launched
remotely. Upgrading to version 2.0.9 is able to address this issue. The
name of the patch is a07b7b08084b9b85859f3968ce7fde0fd1fcbba3. It is recommended
to upgrade the affected component. The identifier of this vulnerability
is VDB-259628.</p>
</td>
<td rowspan="1" colspan="1">
<p>3.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2014-125111</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2011-10006</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in GamerZ WP-PostRatings up to 1.64. It has
been classified as problematic. This affects an unknown part of the file
wp-postratings.php. The manipulation leads to cross site scripting. It
is possible to initiate the attack remotely. Upgrading to version 1.65
is able to address this issue. The identifier of the patch is 6182a5682b12369ced0becd3b505439ce2eb8132.
It is recommended to upgrade the affected component. The identifier VDB-259629
was assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>3.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2011-10006</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3433</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability classified as problematic has been found in PuneethReddyHC
Event Management 1.0. Affected is an unknown function of the file /backend/register.php.
The manipulation of the argument event_id/full_name/email/mobile/college/branch
leads to cross site scripting. It is possible to launch the attack remotely.
VDB-259614 is the identifier assigned to this vulnerability. NOTE: The
vendor was contacted early about this disclosure but did not respond in
any way.</p>
</td>
<td rowspan="1" colspan="1">
<p>3.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3433</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3428</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability has been found in SourceCodester Online Courseware 1.0
and classified as problematic. This vulnerability affects unknown code
of the file edit.php. The manipulation of the argument id leads to cross
site scripting. The attack can be initiated remotely. The exploit has been
disclosed to the public and may be used. The identifier of this vulnerability
is VDB-259600.</p>
</td>
<td rowspan="1" colspan="1">
<p>3.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3428</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3427</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability, which was classified as problematic, was found in SourceCodester
Online Courseware 1.0. This affects an unknown part of the file addq.php.
The manipulation of the argument id leads to cross site scripting. It is
possible to initiate the attack remotely. The exploit has been disclosed
to the public and may be used. The associated identifier of this vulnerability
is VDB-259599.</p>
</td>
<td rowspan="1" colspan="1">
<p>3.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3427</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3426</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability, which was classified as problematic, has been found in
SourceCodester Online Courseware 1.0. Affected by this issue is some unknown
functionality of the file editt.php. The manipulation of the argument id
leads to cross site scripting. The attack may be launched remotely. The
exploit has been disclosed to the public and may be used. VDB-259598 is
the identifier assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>3.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3426</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3415</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Human Resource Information
System 1.0. It has been classified as problematic. Affected is an unknown
function of the file Superadmin_Dashboard/process/addbranches_process.php.
The manipulation of the argument branches_name leads to cross site scripting.
It is possible to launch the attack remotely. The exploit has been disclosed
to the public and may be used. The identifier of this vulnerability is
VDB-259584.</p>
</td>
<td rowspan="1" colspan="1">
<p>3.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3415</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3414</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Human Resource Information
System 1.0 and classified as problematic. This issue affects some unknown
processing of the file Superadmin_Dashboard/process/addcorporate_process.php.
The manipulation of the argument corporate_name leads to cross site scripting.
The attack may be initiated remotely. The exploit has been disclosed to
the public and may be used. The associated identifier of this vulnerability
is VDB-259583.</p>
</td>
<td rowspan="1" colspan="1">
<p>3.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3414</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3366</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability classified as problematic was found in Xuxueli xxl-job
up to 2.4.1. This vulnerability affects the function deserialize of the
file com/xxl/job/core/util/<a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">JdkSerializeTool.java</a> of the component
Template Handler. The manipulation leads to injection. The exploit has
been disclosed to the public and may be used. The identifier of this vulnerability
is VDB-259480.</p>
</td>
<td rowspan="1" colspan="1">
<p>3.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3366</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3365</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Online Library System 1.0.
It has been rated as problematic. This issue affects some unknown processing
of the file admin/users/controller.php. The manipulation of the argument
user_name leads to cross site scripting. The attack may be initiated remotely.
The exploit has been disclosed to the public and may be used. The identifier
VDB-259469 was assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>3.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3365</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3364</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester Online Library System 1.0.
It has been declared as problematic. This vulnerability affects unknown
code of the file admin/books/index.php. The manipulation of the argument
id leads to cross site scripting. The attack can be initiated remotely.
The exploit has been disclosed to the public and may be used. The identifier
of this vulnerability is VDB-259468.</p>
</td>
<td rowspan="1" colspan="1">
<p>3.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3364</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3358</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability classified as problematic was found in SourceCodester
Aplaya Beach Resort Online Reservation System 1.0. This vulnerability affects
unknown code of the file /index.php. The manipulation of the argument to
leads to cross site scripting. The attack can be initiated remotely. The
exploit has been disclosed to the public and may be used. VDB-259462 is
the identifier assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>3.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3358</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3357</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability classified as problematic has been found in SourceCodester
Aplaya Beach Resort Online Reservation System 1.0. This affects an unknown
part of the file admin/mod_reports/index.php. The manipulation of the argument
end leads to cross site scripting. It is possible to initiate the attack
remotely. The exploit has been disclosed to the public and may be used.
The identifier VDB-259461 was assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>3.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3357</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31213</p>
</td>
<td rowspan="1" colspan="1">
<p>InstantCMS is a free and open source content management system. An open
redirect was found in the ICMS2 application version 2.16.2 when being redirected
after modifying one's own user profile. An attacker could trick a victim
into visiting their web application, thinking they are still present on
the ICMS2 application. They could then host a website stating "To update
your profile, please enter your password," upon which the user may type
their password and send it to the attacker. As of time of publication,
a patched version is not available.</p>
</td>
<td rowspan="1" colspan="1">
<p>3.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31213</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3321</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability classified as problematic has been found in SourceCodester
eLearning System 1.0. This affects an unknown part of the component Maintenance
Module. The manipulation of the argument Subject Code/Description leads
to cross site scripting. It is possible to initiate the attack remotely.
The exploit has been disclosed to the public and may be used. The identifier
VDB-259389 was assigned to this vulnerability.</p>
</td>
<td rowspan="1" colspan="1">
<p>3.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3321</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3320</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in SourceCodester eLearning System 1.0. It has
been rated as problematic. Affected by this issue is some unknown functionality.
The manipulation of the argument page leads to cross site scripting. The
attack may be launched remotely. The identifier of this vulnerability is
VDB-259388.</p>
</td>
<td rowspan="1" colspan="1">
<p>3.5</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3320</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26277</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability has been identified in Parasolid V35.1 (All versions &lt;
V35.1.254), Parasolid V36.0 (All versions &lt; V36.0.207), Parasolid V36.1
(All versions &lt; V36.1.147). The affected applications contain a null
pointer dereference vulnerability while parsing specially crafted X_T files.
An attacker could leverage this vulnerability to crash the application
causing denial of service condition.</p>
</td>
<td rowspan="1" colspan="1">
<p>3.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26277</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26276</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability has been identified in Parasolid V35.1 (All versions &lt;
V35.1.254), Parasolid V36.0 (All versions &lt; V36.0.207), Parasolid V36.1
(All versions &lt; V36.1.147). The affected application contains a stack
exhaustion vulnerability while parsing a specially crafted X_T file. This
could allow an attacker to cause denial of service condition.</p>
</td>
<td rowspan="1" colspan="1">
<p>3.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26276</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-0076</p>
</td>
<td rowspan="1" colspan="1">
<p>
<br>NVIDIA CUDA toolkit for all platforms contains a vulnerability in cuobjdump
and nvdisasm where an attacker may cause a crash by tricking a user into
reading a malformed ELF file. A successful exploit of this vulnerability
may lead to a partial denial of service.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>3.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-0076</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-0072</p>
</td>
<td rowspan="1" colspan="1">
<p>
<br>NVIDIA CUDA toolkit for all platforms contains a vulnerability in cuobjdump
and nvdisasm where an attacker may cause a crash by tricking a user into
reading a malformed ELF file. A successful exploit of this vulnerability
may lead to a partial denial of service.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>3.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-0072</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30266</p>
</td>
<td rowspan="1" colspan="1">
<p>wasmtime is a runtime for WebAssembly. The 19.0.0 release of Wasmtime
contains a regression introduced during its development which can lead
to a guest WebAssembly module causing a panic in the host runtime. A valid
WebAssembly module, when executed at runtime, may cause this panic. This
vulnerability has been patched in version 19.0.1.</p>
</td>
<td rowspan="1" colspan="1">
<p>3.3</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30266</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28191</p>
</td>
<td rowspan="1" colspan="1">
<p>Contao is an open source content management system. Starting in version
4.0.0 and prior to version 4.13.40 and 5.3.4, it is possible to inject
insert tags in frontend forms if the output is structured in a very specific
way. Contao versions 4.13.40 and 5.3.4 have a patch for this issue. As
a workaround, do not output user data from frontend forms next to each
other, always separate them by at least one character.</p>
</td>
<td rowspan="1" colspan="1">
<p>3.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28191</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-21848</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Access Control in Mattermost Server versions 8.1.x before 8.1.11
allows an attacker that is in a channel with an active call to keep participating
in the call even if they are removed from the channel
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>3.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-21848</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3181</p>
</td>
<td rowspan="1" colspan="1">
<p>Concrete CMS version 9 prior to 9.2.8 and previous versions prior to 8.5.16
are vulnerable to Stored XSS in the Search Field.&nbsp;Prior to the fix,
stored XSS could be executed by an administrator changing a filter to which
a rogue administrator had previously added malicious code.&nbsp;The Concrete
CMS security team gave this vulnerability a CVSS v3.1 score of 3.1 with
a vector of AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:L <a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator</a> .&nbsp;Thanks
Alexey Solovyev for reporting
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>3.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3181</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3180</p>
</td>
<td rowspan="1" colspan="1">
<p>Concrete CMS version 9 below 9.2.8 and previous versions below 8.5.16
is vulnerable to Stored XSS in blocks of type file.&nbsp;Prior to fix,
stored XSS could be caused by a rogue administrator adding malicious code
to the link-text field when creating a block of type file.&nbsp;The Concrete
CMS security team gave this vulnerability a CVSS v3.1 score of 3.1 with
a vector of AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:L <a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator</a> .&nbsp;Thanks
Alexey Solovyev for reporting.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>3.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3180</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3179</p>
</td>
<td rowspan="1" colspan="1">
<p>Concrete CMS version 9 before 9.2.8 and previous versions before 8.5.16
are vulnerable to&nbsp;Stored XSS in the Custom Class page editing.&nbsp;Prior
to the fix, a rogue administrator could insert malicious code in the custom
class field due to insufficient validation of administrator provided data.&nbsp;The
Concrete CMS security team gave this vulnerability a CVSS v3.1 score of
3.1 with a vector of AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:L <a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator</a> .
Thanks&nbsp;Alexey Solovyev for reporting.&nbsp;
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>3.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3179</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3178</p>
</td>
<td rowspan="1" colspan="1">
<p>Concrete CMS versions 9 below 9.2.8 and versions below&nbsp;8.5.16 are
vulnerable to&nbsp;Cross-site Scripting (XSS) in the Advanced File Search
Filter.&nbsp;Prior to the fix, a rogue administrator could add malicious
code in the file manager because of insufficient validation of administrator
provided data. All administrators have access to the File Manager and hence
could create a search filter with the malicious code attached. The Concrete
CMS security team gave this vulnerability a CVSS v3.1 score of 3.1 with
a vector of AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:L <a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator</a> .&nbsp;&nbsp;
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>3.1</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3178</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-0080</p>
</td>
<td rowspan="1" colspan="1">
<p>
<br>NVIDIA nvTIFF Library for Windows and Linux contains a vulnerability where
improper input validation might enable an attacker to use a specially crafted
input file. A successful exploit of this vulnerability might lead to a
partial denial of service.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>2.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-0080</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-31028</p>
</td>
<td rowspan="1" colspan="1">
<p>
<br>NVIDIA nvJPEG2000 Library for Windows and Linux contains a vulnerability
where improper input validation might enable an attacker to use a specially
crafted input file. A successful exploit of this vulnerability might lead
to a partial denial of service.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>2.8</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-31028</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30252</p>
</td>
<td rowspan="1" colspan="1">
<p>Livemarks is a browser extension that provides RSS feed bookmark folders.
Versions of Livemarks prior to 3.7 are vulnerable to cross-site request
forgery. A malicious website may be able to coerce the extension to send
an authenticated GET request to an arbitrary URL. An authenticated request
is a request where the cookies of the browser are sent along with the request.
The <code>subscribe.js</code> script uses the first parameter from the current
URL location as the URL of the RSS feed to subscribe to and checks that
the RSS feed is valid XML. <code>subscribe.js</code> is accessible by an
attacker website due to its use in <code>subscribe.html</code>, an HTML
page that is declared as a <code>web_accessible_resource</code> in <code>manifest.json</code>.
This issue may lead to <code>Privilege Escalation</code>. A CSRF breaks
the integrity of servers running on a private network. A user of the browser
extension may have a private server with dangerous functionality, which
is assumed to be safe due to network segmentation. Upon receiving an authenticated
request instantiated from an attacker, this integrity is broken. Version
3.7 fixes this issue by removing subscribe.html from <code>web_accessible_resources</code>.</p>
</td>
<td rowspan="1" colspan="1">
<p>2.6</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30252</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30261</p>
</td>
<td rowspan="1" colspan="1">
<p>Undici is an HTTP/1.1 client, written from scratch for Node.js. An attacker
can alter the <code>integrity</code> option passed to <code>fetch()</code>,
allowing <code>fetch()</code> to accept requests as valid even if they have
been tampered. This vulnerability was patched in version(s) 5.28.4 and
6.11.1.</p>
</td>
<td rowspan="1" colspan="1">
<p>2.6</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30261</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3430</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was found in QKSMS up to 3.9.4 on Android. It has been
classified as problematic. This affects an unknown part of the file androidmanifest.xml
of the component Backup File Handler. The manipulation leads to exposure
of backup file to an unauthorized control sphere. It is possible to launch
the attack on the physical device. The exploit has been disclosed to the
public and may be used. The associated identifier of this vulnerability
is VDB-259611. NOTE: The vendor was contacted early about this disclosure
but did not respond in any way.</p>
</td>
<td rowspan="1" colspan="1">
<p>2.4</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3430</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2753</p>
</td>
<td rowspan="1" colspan="1">
<p>Concrete CMS version 9 before 9.2.8 and previous versions prior to 8.5.16
is vulnerable to Stored XSS on the calendar color settings screen since
Information input by the user is output without escaping. A rogue administrator
could inject malicious javascript into the Calendar Color Settings screen
which might be executed when users visit the affected page. The Concrete
CMS security team gave this vulnerability a CVSS v3.1 score of 2.0 with
a vector of AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N&amp;version=3.1 <a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator</a> &nbsp;
<br>
<br>Thank you Rikuto Tauchi for reporting</p>
</td>
<td rowspan="1" colspan="1">
<p>2</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2753</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3556</p>
</td>
<td rowspan="1" colspan="1">
<p>Rejected reason: Duplicate of CVE-2024-3557</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3556</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27665</p>
</td>
<td rowspan="1" colspan="1">
<p>Unifiedtransform v2.X is vulnerable to Stored Cross-Site Scripting (XSS)
via file upload feature in Syllabus module.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27665</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3545</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper permission handling in the vault offline cache feature in Devolutions
Remote Desktop Manager 2024.1.20 and earlier on windows and Devolutions
Server 2024.1.8 and earlier allows an attacker to access sensitive informations
contained in the offline cache file by gaining access to a computer where
the software is installed even though the offline mode is disabled.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3545</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30706</p>
</td>
<td rowspan="1" colspan="1">
<p>An issue was discovered in ROS2 Dashing Diademata versions ROS_VERSION
is 2 and ROS_PYTHON_VERSION is 3, allows remote attackers to execute arbitrary
code, escalate privileges, obtain sensitive information, and gain unauthorized
access to multiple ROS2 nodes.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30706</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2918</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper input validation in PAM JIT elevation feature in Devolutions
Server 2024.1.6 and earlier allows an attacker with access to the PAM JIT
elevation feature to forge the displayed group in the PAM JIT elevation
checkout request via a specially crafted request.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2918</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-24245</p>
</td>
<td rowspan="1" colspan="1">
<p>An issue in Canimaan Software LTD ClamXAV v3.1.2 through v3.6.1 and fixed
in v.3.6.2 allows a local attacker to escalate privileges via the ClamXAV
helper tool component.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-24245</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31507</p>
</td>
<td rowspan="1" colspan="1">
<p>Sourcecodester Online Graduate Tracer System v1.0 is vulnerable to SQL
Injection via the "request" parameter in admin/fetch_gendercs.php.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31507</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31506</p>
</td>
<td rowspan="1" colspan="1">
<p>Sourcecodester Online Graduate Tracer System v1.0 is vulnerable to SQL
Injection via the "id" parameter in admin/admin_cs.php.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31506</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30704</p>
</td>
<td rowspan="1" colspan="1">
<p>An insecure deserialization vulnerability has been identified in ROS2
Galactic Geochelone ROS_VERSION 2 and ROS_PYTHON_VERSION 3, allows attackers
to execute arbitrary code and obtain sensitive information via crafted
input to the Data Serialization and Deserialization Components, Inter-Process
Communication Mechanisms, and Network Communication Interfaces.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30704</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30703</p>
</td>
<td rowspan="1" colspan="1">
<p>An arbitrary file upload vulnerability has been discovered in ROS2 (Robot
Operating System 2) Galactic Geochelone ROS_VERSION 2 and ROS_PYTHON_VERSION
3, allows attackers to execute arbitrary code, cause a denial of service
(DoS), and obtain sensitive information via a crafted payload to the file
upload mechanism of the ROS2 system, including the server’s functionality
for handling file uploads and the associated validation processes.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30703</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30702</p>
</td>
<td rowspan="1" colspan="1">
<p>An issue was discovered in ROS2 Galactic Geochelone in ROS_VERSION 2 and
ROS_PYTHON_VERSION 3, allows remote attackers to execute arbitrary code
via packages or nodes within the ROS2 system.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30702</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31867</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Input Validation vulnerability in Apache Zeppelin.
<br>
<br>The attackers can execute malicious queries by setting improper configuration
properties to LDAP search filter.
<br>This issue affects Apache Zeppelin: from 0.8.2 before 0.11.1.
<br>
<br>Users are recommended to upgrade to version 0.11.1, which fixes the issue.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31867</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3281</p>
</td>
<td rowspan="1" colspan="1">
<p>A vulnerability was discovered in the firmware builds after 8.0.2.3267
and prior to 8.1.3.1301 in CCX devices. A flaw in the firmware build process
did not properly restrict access to a resource from an unauthorized actor.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3281</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31868</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Encoding or Escaping of Output vulnerability in Apache Zeppelin.
<br>
<br>The attackers can modify helium.json and exposure XSS attacks to normal
users.
<br>This issue affects Apache Zeppelin: from 0.8.2 before 0.11.1.
<br>
<br>Users are recommended to upgrade to version 0.11.1, which fixes the issue.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31868</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31866</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Encoding or Escaping of Output vulnerability in Apache Zeppelin.
<br>
<br>The attackers can execute shell scripts or malicious code by overriding
configuration like&nbsp;ZEPPELIN_INTP_CLASSPATH_OVERRIDES.
<br>This issue affects Apache Zeppelin: from 0.8.2 before 0.11.1.
<br>
<br>Users are recommended to upgrade to version 0.11.1, which fixes the issue.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31866</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31865</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Input Validation vulnerability in Apache Zeppelin.
<br>
<br>The attackers can call updating cron API with invalid or improper privileges
so that the notebook can run with the privileges.
<br>
<br>This issue affects Apache Zeppelin: from 0.8.2 before 0.11.1.
<br>
<br>Users are recommended to upgrade to version 0.11.1, which fixes the issue.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31865</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31864</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Control of Generation of Code ('Code Injection') vulnerability
in Apache Zeppelin.
<br>
<br>The attacker can inject sensitive configuration or malicious code when
connecting MySQL database via JDBC driver.
<br>This issue affects Apache Zeppelin: before 0.11.1.
<br>
<br>Users are recommended to upgrade to version 0.11.1, which fixes the issue.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31864</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31544</p>
</td>
<td rowspan="1" colspan="1">
<p>A stored cross-site scripting (XSS) vulnerability in Computer Laboratory
Management System v1.0 allows attackers to execute arbitrary JavaScript
code by including malicious payloads into “remarks”, “borrower_name”, “faculty_department”
parameters in /classes/Master.php?f=save_record.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31544</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31863</p>
</td>
<td rowspan="1" colspan="1">
<p>Authentication Bypass by Spoofing vulnerability by replacing to exsiting
notes in Apache Zeppelin.This issue affects Apache Zeppelin: from 0.10.1
before 0.11.0.
<br>
<br>Users are recommended to upgrade to version 0.11.0, which fixes the issue.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31863</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31862</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Input Validation vulnerability in Apache Zeppelin when creating
a new note from Zeppelin's UI.This issue affects Apache Zeppelin: from
0.10.1 before 0.11.0.
<br>
<br>Users are recommended to upgrade to version 0.11.0, which fixes the issue.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31862</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2022-47894</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Input Validation vulnerability in Apache Zeppelin SAP.This issue
affects Apache Zeppelin SAP: from 0.8.0 before 0.11.0.
<br>
<br>As this project is retired, we do not plan to release a version that fixes
this issue. Users are recommended to find an alternative or restrict access
to the instance to trusted users.
<br>
<br>For more information, the fix already was merged in the source code but
Zeppelin decided to retire the SAP component
<br>NOTE: This vulnerability only affects products that are no longer supported
by the maintainer.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2022-47894</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2021-28656</p>
</td>
<td rowspan="1" colspan="1">
<p>Cross-Site Request Forgery (CSRF) vulnerability in Credential page of
Apache Zeppelin allows an attacker to submit malicious request. This issue
affects Apache Zeppelin Apache Zeppelin version 0.9.0 and prior versions.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2021-28656</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31860</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper Input Validation vulnerability in Apache Zeppelin.
<br>
<br>By adding relative path indicators(E.g ..), attackers can see the contents
for any files in the filesystem that the server account can access.&nbsp;
<br>This issue affects Apache Zeppelin: from 0.9.0 before 0.11.0.
<br>
<br>Users are recommended to upgrade to version 0.11.0, which fixes the issue.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31860</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30701</p>
</td>
<td rowspan="1" colspan="1">
<p>An insecure logging vulnerability in ROS2 Galactic Geochelone ROS_VERSION
2 and ROS_PYTHON_VERSION 3, allows attackers to obtain sensitive information
via inadequate security measures implemented within the logging mechanisms
of ROS2.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30701</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30699</p>
</td>
<td rowspan="1" colspan="1">
<p>A buffer overflow vulnerability has been discovered in the C++ components
of ROS2 Galactic Geochelone ROS_VERSION 2 and ROS_PYTHON_VERSION 3, allows
attackers to execute arbitrary code or cause a denial of service (DoS)
via improper handling of arrays or strings.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30699</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30697</p>
</td>
<td rowspan="1" colspan="1">
<p>An issue was discovered in ROS2 Galactic Geochelone in ROS_VERSION 2 and
ROS_PYTHON_VERSION 3, where the system transmits messages in plaintext,
allowing attackers to access sensitive information via a man-in-the-middle
attack.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30697</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30696</p>
</td>
<td rowspan="1" colspan="1">
<p>OS command injection vulnerability in ROS2 Galactic Geochelone in ROS_VERSION
2 and ROS_PYTHON_VERSION 3, allows remote attackers to execute arbitrary
code, escalate privileges, and obtain sensitive information via the command
processing or system call components in ROS2, including External Command
Execution Modules, System Call Handlers, and Interface Scripts.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30696</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30695</p>
</td>
<td rowspan="1" colspan="1">
<p>An issue was discovered in the default configurations of ROS2 Galactic
Geochelone versions ROS_VERSION 2 and ROS_PYTHON_VERSION 3, allows unauthenticated
attackers to gain access using default credentials.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30695</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30694</p>
</td>
<td rowspan="1" colspan="1">
<p>A shell injection vulnerability was discovered in ROS2 (Robot Operating
System 2) Galactic Geochelone ROS_VERSION 2 and ROS_PYTHON_VERSION 3, allows
attackers to execute arbitrary code, escalate privileges, and obtain sensitive
information due to the way ROS2 handles shell command execution in components
like command interpreters or interfaces that process external inputs.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30694</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30692</p>
</td>
<td rowspan="1" colspan="1">
<p>A issue was discovered in ROS2 Galactic Geochelone versions ROS_VERSION
2 and ROS_PYTHON_VERSION 3, allows remote attackers to cause a denial of
service (DoS) in the ROS2 nodes.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30692</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30691</p>
</td>
<td rowspan="1" colspan="1">
<p>An issue was discovered in ROS2 Galactic Geochelone in version ROS_VERSION
2 and ROS_PYTHON_VERSION 3, allows remote attackers to execute arbitrary
code, escalate privileges, obtain sensitive information, and gain unauthorized
access to multiple ROS2 nodes.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30691</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30690</p>
</td>
<td rowspan="1" colspan="1">
<p>An unauthorized node injection vulnerability has been identified in ROS2
Galactic Geochelone versions where ROS_VERSION is 2 and ROS_PYTHON_VERSION
is 3, allows remote attackers to escalate privileges.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30690</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30688</p>
</td>
<td rowspan="1" colspan="1">
<p>An arbitrary file upload vulnerability has been discovered in ROS2 Iron
Irwini versions ROS_VERSION 2 and ROS_PYTHON_VERSION 3, allows attackers
to execute arbitrary code via a crafted payload to the file upload mechanism
of the ROS2 system, including the server’s functionality for handling file
uploads and the associated validation processes.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30688</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30687</p>
</td>
<td rowspan="1" colspan="1">
<p>An insecure deserialization vulnerability has been identified in ROS2
Iron Irwini versions ROS_VERSION 2 and ROS_PYTHON_VERSION 3, allows attackers
to execute arbitrary code via a crafted input to the Data Serialization
and Deserialization Components, Inter-Process Communication Mechanisms,
and Network Communication Interfaces.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30687</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30686</p>
</td>
<td rowspan="1" colspan="1">
<p>An issue was discovered in ROS2 Iron Irwini versions ROS_VERSION 2 and
ROS_PYTHON_VERSION 3, allows remote attackers to execute arbitrary code
via packages or nodes within the ROS2 system.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30686</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30684</p>
</td>
<td rowspan="1" colspan="1">
<p>An insecure logging vulnerability has been identified within ROS2 Iron
Irwini versions ROS_VERSION 2 and ROS_PYTHON_VERSION 3, allows attackers
to access sensitive information via inadequate security measures implemented
within the logging mechanisms of ROS2.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30684</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1664</p>
</td>
<td rowspan="1" colspan="1">
<p>The Responsive Gallery Grid WordPress plugin before 2.3.11 does not sanitise
and escape some of its settings, which could allow high privilege users
such as admin to perform Stored Cross-Site Scripting attacks even when
the unfiltered_html capability is disallowed (for example in multisite
setup)</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1664</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30683</p>
</td>
<td rowspan="1" colspan="1">
<p>A buffer overflow vulnerability has been discovered in the C++ components
of ROS2 Iron Irwini versions ROS_VERSION 2 and ROS_PYTHON_VERSION 3, allows
attackers to execute arbitrary code or cause a Denial of Service (DoS)
via improper handling of arrays or strings.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30683</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30681</p>
</td>
<td rowspan="1" colspan="1">
<p>An OS command injection vulnerability has been discovered in ROS2 Iron
Irwini version ROS_VERSION 2 and ROS_PYTHON_VERSION 3, allows attackers
to execute arbitrary code, escalate privileges, and obtain sensitive information
via the command processing or system call components in ROS2.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30681</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30680</p>
</td>
<td rowspan="1" colspan="1">
<p>Shell injection vulnerability was discovered in ROS2 (Robot Operating
System 2) Iron Irwini in versions ROS_VERSION 2 and ROS_PYTHON_VERSION
3, allows attackers to execute arbitrary code escalate privileges, and
obtain sensitive information due to the way ROS2 handles shell command
execution in components like command interpreters or interfaces that process
external inputs.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30680</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30679</p>
</td>
<td rowspan="1" colspan="1">
<p>An issue was discovered in the default configurations of ROS2 Iron Irwini
ROS_VERSION 2 and ROS_PYTHON_VERSION 3, allows unauthenticated attackers
to authenticate using default credentials.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30679</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30678</p>
</td>
<td rowspan="1" colspan="1">
<p>An issue has been discovered in ROS2 Iron Irwini ROS_VERSION 2 and ROS_PYTHON_VERSION
3, where the system transmits messages in plaintext. This flaw exposes
sensitive information, making it vulnerable to man-in-the-middle (MitM)
attacks, and allowing attackers to intercept and access this data.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30678</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30676</p>
</td>
<td rowspan="1" colspan="1">
<p>A Denial-of-Service (DoS) vulnerability exists in ROS2 Iron Irwini versions
where ROS_VERSION is 2 and ROS_PYTHON_VERSION is 3. A malicious user could
potentially exploit this vulnerability remotely to crash the ROS2 nodes,
thereby causing a denial of service. The flaw allows an attacker to cause
unexpected behavior in the operation of ROS2 nodes, which leads to their
failure and interrupts the regular operation of the system, thus making
it unavailable for its intended users.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30676</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27983</p>
</td>
<td rowspan="1" colspan="1">
<p>An attacker can make the Node.js HTTP/2 server completely unavailable
by sending a small amount of HTTP/2 frames packets with a few HTTP/2 frames
inside. It is possible to leave some data in nghttp2 memory after reset
when headers with HTTP/2 CONTINUATION frame are sent to the server and
then a TCP connection is abruptly closed by the client triggering the Http2Session
destructor while header frames are still being processed (and stored in
memory) causing a race condition.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27983</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31047</p>
</td>
<td rowspan="1" colspan="1">
<p>An issue in Academy Software Foundation openexr v.3.2.3 and before allows
a local attacker to cause a denial of service (DoS) via the convert function
of exrmultipart.cpp.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31047</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-23084</p>
</td>
<td rowspan="1" colspan="1">
<p>Apfloat v1.10.1 was discovered to contain an ArrayIndexOutOfBoundsException
via the component org.apfloat.internal.DoubleCRTMath::add(double[], double[]).</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-23084</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-23081</p>
</td>
<td rowspan="1" colspan="1">
<p>ThreeTen Backport v1.6.8 was discovered to contain a NullPointerException
via the component org.threeten.bp.LocalDate::compareTo(ChronoLocalDate).</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-23081</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-23079</p>
</td>
<td rowspan="1" colspan="1">
<p>JGraphT Core v1.5.2 was discovered to contain a NullPointerException via
the component org.jgrapht.alg.util.ToleranceDoubleComparator::compare(Double,
Double).</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-23079</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-22949</p>
</td>
<td rowspan="1" colspan="1">
<p>JFreeChart v1.5.4 was discovered to contain a NullPointerException via
the component /chart/annotations/CategoryLineAnnotation.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-22949</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27632</p>
</td>
<td rowspan="1" colspan="1">
<p>An issue in GNU Savane v.3.12 and before allows a remote attacker to escalate
privileges via the form_id in the form_header() function.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27632</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27631</p>
</td>
<td rowspan="1" colspan="1">
<p>Cross Site Request Forgery vulnerability in GNU Savane v.3.12 and before
allows a remote attacker to escalate privileges via siteadmin/usergroup.php</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27631</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27630</p>
</td>
<td rowspan="1" colspan="1">
<p>Insecure Direct Object Reference (IDOR) in GNU Savane v.3.12 and before
allows a remote attacker to delete arbitrary files via crafted input to
the trackers_data_delete_file function.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27630</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-24279</p>
</td>
<td rowspan="1" colspan="1">
<p>An issue in secdiskapp 1.5.1 (management program for NewQ Fingerprint
Encryption Super Speed Flash Disk) allows attackers to gain escalated privileges
via vsVerifyPassword and vsSetFingerPrintPower functions.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-24279</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-23086</p>
</td>
<td rowspan="1" colspan="1">
<p>Apfloat v1.10.1 was discovered to contain a stack overflow via the component
org.apfloat.internal.DoubleModMath::modPow(double.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-23086</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-23085</p>
</td>
<td rowspan="1" colspan="1">
<p>Apfloat v1.10.1 was discovered to contain a NullPointerException via the
component org.apfloat.internal.DoubleScramble::scramble(double[], int,
int[]).</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-23085</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-23078</p>
</td>
<td rowspan="1" colspan="1">
<p>JGraphT Core v1.5.2 was discovered to contain a NullPointerException via
the component org.jgrapht.alg.util.ToleranceDoubleComparator::compare(Double,
Double).</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-23078</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28270</p>
</td>
<td rowspan="1" colspan="1">
<p>An issue discovered in web-flash v3.0 allows attackers to reset passwords
for arbitrary users via crafted POST request to /prod-api/user/resetPassword.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28270</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28224</p>
</td>
<td rowspan="1" colspan="1">
<p>Ollama before 0.1.29 has a DNS rebinding vulnerability that can inadvertently
allow remote access to the full API, thereby letting an unauthorized user
chat with a large language model, delete a model, or cause a denial of
service (resource exhaustion).</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28224</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-23082</p>
</td>
<td rowspan="1" colspan="1">
<p>ThreeTen Backport v1.6.8 was discovered to contain an integer overflow
via the component org.threeten.bp.format.DateTimeFormatter::parse(CharSequence,
ParsePosition).</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-23082</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-7164</p>
</td>
<td rowspan="1" colspan="1">
<p>The BackWPup WordPress plugin before 4.0.4 does not prevent visitors from
leaking key information about ongoing backups, allowing unauthenticated
attackers to download backups of a site's database.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-7164</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2511</p>
</td>
<td rowspan="1" colspan="1">
<p>Issue summary: Some non-default TLS server configurations can cause unbounded
<br>memory growth when processing TLSv1.3 sessions
<br>
<br>Impact summary: An attacker may exploit certain server configurations
to trigger
<br>unbounded memory growth that would lead to a Denial of Service
<br>
<br>This problem can occur in TLSv1.3 if the non-default SSL_OP_NO_TICKET
option is
<br>being used (but not if early_data support is also configured and the default
<br>anti-replay protection is in use). In this case, under certain conditions,
the
<br>session cache can get into an incorrect state and it will fail to flush
properly
<br>as it fills. The session cache will continue to grow in an unbounded manner.
A
<br>malicious client could deliberately create the scenario for this failure
to
<br>force a Denial of Service. It may also happen by accident in normal operation.
<br>
<br>This issue only affects TLS servers supporting TLSv1.3. It does not affect
TLS
<br>clients.
<br>
<br>The FIPS modules in 3.2, 3.1 and 3.0 are not affected by this issue. OpenSSL
<br>1.0.2 is also not affected by this issue.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2511</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28732</p>
</td>
<td rowspan="1" colspan="1">
<p>An issue was discovered in OFPMatch in <a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">parser.py</a> in Faucet SDN Ryu version 4.34,
allows remote attackers to cause a denial of service (DoS) (infinite loop).</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28732</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31817</p>
</td>
<td rowspan="1" colspan="1">
<p>In TOTOLINK EX200 V4.0.3c.7646_B20201211, an attacker can obtain sensitive
information without authorization through the function getSysStatusCfg.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31817</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31816</p>
</td>
<td rowspan="1" colspan="1">
<p>In TOTOLINK EX200 V4.0.3c.7646_B20201211, an attacker can obtain sensitive
information without authorization through the function getEasyWizardCfg.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31816</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31815</p>
</td>
<td rowspan="1" colspan="1">
<p>In TOTOLINK EX200 V4.0.3c.7314_B20191204, an attacker can obtain the configuration
file without authorization through /cgi-bin/<a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">ExportSettings.sh</a>
</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31815</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31814</p>
</td>
<td rowspan="1" colspan="1">
<p>TOTOLINK EX200 V4.0.3c.7646_B20201211 allows attackers to bypass login
through the Form_Login function.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31814</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31813</p>
</td>
<td rowspan="1" colspan="1">
<p>TOTOLINK EX200 V4.0.3c.7646_B20201211 does not contain an authentication
mechanism by default.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31813</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31812</p>
</td>
<td rowspan="1" colspan="1">
<p>In TOTOLINK EX200 V4.0.3c.7646_B20201211, an attacker can obtain sensitive
information without authorization through the function getWiFiExtenderConfig.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31812</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31811</p>
</td>
<td rowspan="1" colspan="1">
<p>TOTOLINK EX200 V4.0.3c.7646_B20201211 was discovered to contain a remote
code execution (RCE) vulnerability via the langType parameter in the setLanguageCfg
function.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31811</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31809</p>
</td>
<td rowspan="1" colspan="1">
<p>TOTOLINK EX200 V4.0.3c.7646_B20201211 was discovered to contain a remote
code execution (RCE) vulnerability via the FileName parameter in the setUpgradeFW
function.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31809</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31808</p>
</td>
<td rowspan="1" colspan="1">
<p>TOTOLINK EX200 V4.0.3c.7646_B20201211 was discovered to contain a remote
code execution (RCE) vulnerability via the webWlanIdx parameter in the
setWebWlanIdx function.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31808</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31807</p>
</td>
<td rowspan="1" colspan="1">
<p>TOTOLINK EX200 V4.0.3c.7646_B20201211 was discovered to contain a remote
code execution (RCE) vulnerability via the hostTime parameter in the NTPSyncWithHost
function.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31807</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31806</p>
</td>
<td rowspan="1" colspan="1">
<p>TOTOLINK EX200 V4.0.3c.7646_B20201211 was discovered to contain a Denial-of-Service
(DoS) vulnerability in the RebootSystem function which can reboot the system
without authorization.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31806</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31805</p>
</td>
<td rowspan="1" colspan="1">
<p>TOTOLINK EX200 V4.0.3c.7646_B20201211 allows attackers to start the Telnet
service without authorization via the telnet_enabled parameter in the setTelnetCfg
function.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31805</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28066</p>
</td>
<td rowspan="1" colspan="1">
<p>In Unify CP IP Phone firmware 1.10.4.3, Weak Credentials are used (a hardcoded
root password).</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28066</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26574</p>
</td>
<td rowspan="1" colspan="1">
<p>Insecure Permissions vulnerability in Wondershare Filmora v.13.0.51 allows
a local attacker to execute arbitrary code via a crafted script to the
WSNativePushService.exe</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26574</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2022-43216</p>
</td>
<td rowspan="1" colspan="1">
<p>AbrhilSoft Employee's Portal before v5.6.2 was discovered to contain a
SQL injection vulnerability in the login page.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2022-43216</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27897</p>
</td>
<td rowspan="1" colspan="1">
<p>Input verification vulnerability in the call module.
<br>Impact: Successful exploitation of this vulnerability may affect service
confidentiality.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27897</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27896</p>
</td>
<td rowspan="1" colspan="1">
<p>Input verification vulnerability in the log module.
<br>Impact: Successful exploitation of this vulnerability can affect integrity.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27896</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27895</p>
</td>
<td rowspan="1" colspan="1">
<p>Vulnerability of permission control in the window module. Successful exploitation
of this vulnerability may affect confidentiality.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27895</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26811</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>ksmbd: validate payload size in ipc response
<br>
<br>If installing malicious ksmbd-tools, ksmbd.mountd can return invalid ipc
<br>response to ksmbd kernel server. ksmbd should validate payload size of
<br>ipc response from ksmbd.mountd to avoid memory overrun or
<br>slab-out-of-bounds. This patch validate 3 ipc response that has payload.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26811</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52386</p>
</td>
<td rowspan="1" colspan="1">
<p>Out-of-bounds write vulnerability in the RSMC module.
<br>Impact: Successful exploitation of this vulnerability will affect availability.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52386</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52385</p>
</td>
<td rowspan="1" colspan="1">
<p>Out-of-bounds write vulnerability in the RSMC module.
<br>Impact: Successful exploitation of this vulnerability will affect availability.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52385</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52364</p>
</td>
<td rowspan="1" colspan="1">
<p>Vulnerability of input parameters being not strictly verified in the RSMC
module.
<br>Impact: Successful exploitation of this vulnerability may cause out-of-bounds
write.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52364</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52554</p>
</td>
<td rowspan="1" colspan="1">
<p>Permission control vulnerability in the Bluetooth module.
<br>Impact: Successful exploitation of this vulnerability may affect service
confidentiality.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52554</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52553</p>
</td>
<td rowspan="1" colspan="1">
<p>Race condition vulnerability in the Wi-Fi module.
<br>Impact: Successful exploitation of this vulnerability will affect availability.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52553</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52552</p>
</td>
<td rowspan="1" colspan="1">
<p>Input verification vulnerability in the power module.
<br>Impact: Successful exploitation of this vulnerability will affect availability.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52552</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52551</p>
</td>
<td rowspan="1" colspan="1">
<p>Vulnerability of data verification errors in the kernel module.
<br>Impact: Successful exploitation of this vulnerability may affect service
confidentiality.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52551</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52550</p>
</td>
<td rowspan="1" colspan="1">
<p>Vulnerability of data verification errors in the kernel module.
<br>Impact: Successful exploitation of this vulnerability may affect service
confidentiality.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52550</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52549</p>
</td>
<td rowspan="1" colspan="1">
<p>Vulnerability of data verification errors in the kernel module.
<br>Impact: Successful exploitation of this vulnerability may affect service
confidentiality.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52549</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52546</p>
</td>
<td rowspan="1" colspan="1">
<p>Vulnerability of package name verification being bypassed in the Calendar
app.
<br>Impact: Successful exploitation of this vulnerability may affect service
confidentiality.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52546</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52545</p>
</td>
<td rowspan="1" colspan="1">
<p>Vulnerability of undefined permissions in the Calendar app.
<br>Impact: Successful exploitation of this vulnerability will affect availability.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52545</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52544</p>
</td>
<td rowspan="1" colspan="1">
<p>Vulnerability of file path verification being bypassed in the email module.
<br>Impact: Successful exploitation of this vulnerability may affect service
confidentiality.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52544</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52543</p>
</td>
<td rowspan="1" colspan="1">
<p>Permission verification vulnerability in the system module.
<br>Impact: Successful exploitation of this vulnerability will affect availability.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52543</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52542</p>
</td>
<td rowspan="1" colspan="1">
<p>Permission verification vulnerability in the system module.
<br>Impact: Successful exploitation of this vulnerability will affect availability.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52542</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52541</p>
</td>
<td rowspan="1" colspan="1">
<p>Authentication vulnerability in the API for app pre-loading.
<br>Impact: Successful exploitation of this vulnerability may affect service
confidentiality.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52541</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52540</p>
</td>
<td rowspan="1" colspan="1">
<p>Vulnerability of improper authentication in the Iaware module.
<br>Impact: Successful exploitation of this vulnerability will affect availability.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52540</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52539</p>
</td>
<td rowspan="1" colspan="1">
<p>Permission verification vulnerability in the Settings module.
<br>Impact: Successful exploitation of this vulnerability may affect service
confidentiality.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52539</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52538</p>
</td>
<td rowspan="1" colspan="1">
<p>Vulnerability of package name verification being bypassed in the HwIms
module.
<br>Impact: Successful exploitation of this vulnerability will affect availability.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52538</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52537</p>
</td>
<td rowspan="1" colspan="1">
<p>Vulnerability of package name verification being bypassed in the HwIms
module.
<br>Impact: Successful exploitation of this vulnerability will affect availability.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52537</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52388</p>
</td>
<td rowspan="1" colspan="1">
<p>Permission control vulnerability in the clock module.
<br>Impact: Successful exploitation of this vulnerability will affect availability.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52388</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52359</p>
</td>
<td rowspan="1" colspan="1">
<p>Vulnerability of permission verification in some APIs in the ActivityTaskManagerService
module.
<br>Impact: Successful exploitation of this vulnerability will affect availability.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52359</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30675</p>
</td>
<td rowspan="1" colspan="1">
<p>Unauthorized node injection vulnerability in ROS2 Iron Irwini in ROS_VERSION
2 and ROS_PYTHON_VERSION 3. This vulnerability could allow a malicious
user to escalate privileges by injecting malicious ROS2 nodes into the
system remotely.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30675</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30674</p>
</td>
<td rowspan="1" colspan="1">
<p>Unauthorized access vulnerability in ROS2 Iron Irwini in ROS_VERSION is
2 and ROS_PYTHON_VERSION is 3, allows remote attackers to gain control
of multiple ROS2 nodes. Unauthorized information access to these nodes
could result in compromised system integrity, the execution of arbitrary
commands, and disclosure of sensitive information.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30674</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30672</p>
</td>
<td rowspan="1" colspan="1">
<p>Arbitrary file upload vulnerability in ROS (Robot Operating System) Melodic
Morenia in ROS_VERSION 1 and ROS_PYTHON_VERSION 3, allows attackers to
execute arbitrary code, cause a denial of service (DoS), and obtain sensitive
information via the file upload component.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30672</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30667</p>
</td>
<td rowspan="1" colspan="1">
<p>Insecure deserialization vulnerability in ROS (Robot Operating System)
Melodic Morenia in ROS_VERSION 1 and ROS_PYTHON_VERSION 3, allows attackers
to execute arbitrary code or obtain sensitive information via crafted input
to the data handling components.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30667</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30666</p>
</td>
<td rowspan="1" colspan="1">
<p>A buffer overflow vulnerability has been discovered in the C++ components
of ROS (Robot Operating System) Melodic Morenia in ROS_VERSION 1 and ROS_PYTHON_VERSION
3, allows attackers to execute arbitrary code via improper handling of
arrays or strings within these components.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30666</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30665</p>
</td>
<td rowspan="1" colspan="1">
<p>An OS command injection vulnerability has been discovered in ROS (Robot
Operating System) Melodic Morenia in ROS_VERSION 1 and ROS_PYTHON_VERSION
3. This vulnerability primarily affects the command processing or system
call components in ROS, making them susceptible to manipulation by malicious
entities. Through this, unauthorized commands can be executed, leading
to remote code execution (RCE), data theft, and malicious activities. The
affected components include External Command Execution Modules, System
Call Handlers, and Interface Scripts.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30665</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30663</p>
</td>
<td rowspan="1" colspan="1">
<p>An issue was discovered in the default configurations of ROS (Robot Operating
System) Melodic Morenia in ROS_VERSION 1 and ROS_PYTHON_VERSION 3. This
vulnerability allows unauthenticated attackers to gain access using default
credentials, posing a serious threat to the integrity and security of the
system.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30663</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30662</p>
</td>
<td rowspan="1" colspan="1">
<p>An issue was discovered in ROS (Robot Operating System) Melodic Morenia
in ROS_VERSION 1 and ROS_PYTHON_VERSION 3, where the system transmits messages
in plaintext. This flaw exposes sensitive information, making it vulnerable
to man-in-the-middle (MitM) attacks, and allowing attackers to easily intercept
and access this data.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30662</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30661</p>
</td>
<td rowspan="1" colspan="1">
<p>An unauthorized access vulnerability has been discovered in ROS Melodic
Morenia versions where ROS_VERSION is 1 and ROS_PYTHON_VERSION is 3. This
vulnerability could potentially allow a malicious user to gain unauthorized
information access to multiple ROS nodes remotely. Unauthorized information
access to these nodes could result in compromised system integrity, the
execution of arbitrary commands, and disclosure of sensitive information.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30661</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30659</p>
</td>
<td rowspan="1" colspan="1">
<p>Shell Injection vulnerability in ROS (Robot Operating System) Melodic
Morenia versions ROS_VERSION 1 and ROS_PYTHON_VERSION 3, allows attackers
to execute arbitrary code, escalate privileges, and obtain sensitive information.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30659</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31022</p>
</td>
<td rowspan="1" colspan="1">
<p>An issue was discovered in CandyCMS version 1.0.0, allows remote attackers
to execute arbitrary code via the install.php component.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31022</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27488</p>
</td>
<td rowspan="1" colspan="1">
<p>Incorrect Access Control vulnerability in ZLMediaKit versions 1.0 through
8.0, allows remote attackers to escalate privileges and obtain sensitive
information. The application system enables the http API interface by default
and uses the secret parameter method to authenticate the http restful api
interface, but the secret is hardcoded by default.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27488</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1958</p>
</td>
<td rowspan="1" colspan="1">
<p>The WPB Show Core WordPress plugin before 2.7 does not sanitise and escape
a parameter before outputting it back in the page, leading to a Reflected
Cross-Site Scripting which could be used against high privilege users such
as admin or unauthenticated users</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1958</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1956</p>
</td>
<td rowspan="1" colspan="1">
<p>The wpb-show-core WordPress plugin before 2.7 does not sanitise and escape
the parameters before outputting it back in the response of an unauthenticated
request, leading to a Reflected Cross-Site Scripting</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1956</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1752</p>
</td>
<td rowspan="1" colspan="1">
<p>The Font Farsi WordPress plugin through 1.6.6 does not sanitise and escape
some of its settings, which could allow high privilege users such as admin
to perform Stored Cross-Site Scripting attacks even when the unfiltered_html
capability is disallowed (for example in multisite setup)</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1752</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1589</p>
</td>
<td rowspan="1" colspan="1">
<p>The SendPress Newsletters WordPress plugin through 1.23.11.6 does not
sanitise and escape some of its settings, which could allow high privilege
users such as admin to perform Stored Cross-Site Scripting attacks even
when the unfiltered_html capability is disallowed (for example in multisite
setup)</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1589</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1588</p>
</td>
<td rowspan="1" colspan="1">
<p>The SendPress Newsletters WordPress plugin through 1.23.11.6 does not
sanitise and escape some of its settings, which could allow high privilege
users such as admin to perform Stored Cross-Site Scripting attacks even
when the unfiltered_html capability is disallowed (for example in multisite
setup)</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1588</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1292</p>
</td>
<td rowspan="1" colspan="1">
<p>The WPB Show Core WordPress plugin before 2.7 does not sanitise and escape
some parameters before outputting them back in the page, leading to a Reflected
Cross-Site Scripting which could be used against high privilege users such
as admin</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1292</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-23658</p>
</td>
<td rowspan="1" colspan="1">
<p>In camera driver, there is a possible use after free due to a logic error.
This could lead to local denial of service with System execution privileges
needed</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-23658</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52536</p>
</td>
<td rowspan="1" colspan="1">
<p>In faceid service, there is a possible out of bounds read due to a missing
bounds check. This could lead to local denial of service with System execution
privileges needed</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52536</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52535</p>
</td>
<td rowspan="1" colspan="1">
<p>In vsp driver, there is a possible missing verification incorrect input.
This could lead to local denial of service with no additional execution
privileges needed</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52535</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52534</p>
</td>
<td rowspan="1" colspan="1">
<p>In ngmm, there is a possible undefined behavior due to incorrect error
handling. This could lead to remote denial of service with no additional
execution privileges needed</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52534</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52533</p>
</td>
<td rowspan="1" colspan="1">
<p>In modem-ps-nas-ngmm, there is a possible undefined behavior due to incorrect
error handling. This could lead to remote information disclosure no additional
execution privileges needed</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52533</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52352</p>
</td>
<td rowspan="1" colspan="1">
<p>In Network Adapter Service, there is a possible missing permission check.
This could lead to local denial of service with no additional execution
privileges needed</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52352</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52351</p>
</td>
<td rowspan="1" colspan="1">
<p>In ril service, there is a possible out of bounds write due to a missing
bounds check. This could lead to local denial of service with System execution
privileges needed</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52351</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52350</p>
</td>
<td rowspan="1" colspan="1">
<p>In ril service, there is a possible out of bounds write due to a missing
bounds check. This could lead to local denial of service with System execution
privileges needed</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52350</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52349</p>
</td>
<td rowspan="1" colspan="1">
<p>In ril service, there is a possible out of bounds write due to a missing
bounds check. This could lead to local denial of service with System execution
privileges needed</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52349</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52348</p>
</td>
<td rowspan="1" colspan="1">
<p>In ril service, there is a possible out of bounds write due to a missing
bounds check. This could lead to local denial of service with System execution
privileges needed</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52348</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52347</p>
</td>
<td rowspan="1" colspan="1">
<p>In ril service, there is a possible out of bounds write due to a missing
bounds check. This could lead to local denial of service with System execution
privileges needed</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52347</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52346</p>
</td>
<td rowspan="1" colspan="1">
<p>In modem driver, there is a possible system crash due to improper input
validation. This could lead to local information disclosure with System
execution privileges needed</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52346</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52345</p>
</td>
<td rowspan="1" colspan="1">
<p>In modem driver, there is a possible system crash due to improper input
validation. This could lead to local information disclosure with System
execution privileges needed</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52345</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52344</p>
</td>
<td rowspan="1" colspan="1">
<p>In modem-ps-nas-ngmm, there is a possible undefined behavior due to incorrect
error handling. This could lead to remote information disclosure no additional
execution privileges needed</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52344</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52343</p>
</td>
<td rowspan="1" colspan="1">
<p>In SecurityCommand message after as security has been actived., there
is a possible improper input validation. This could lead to remote information
disclosure no additional execution privileges needed</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52343</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52342</p>
</td>
<td rowspan="1" colspan="1">
<p>In modem-ps-nas-ngmm, there is a possible undefined behavior due to incorrect
error handling. This could lead to remote information disclosure no additional
execution privileges needed</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52342</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52341</p>
</td>
<td rowspan="1" colspan="1">
<p>In Plaintext COUNTER CHECK message accepted before AS security activation,
there is a possible missing permission check. This could lead to remote
information disclosure no additional execution privileges needed</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52341</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28744</p>
</td>
<td rowspan="1" colspan="1">
<p>The password is empty in the initial configuration of ACERA 9010-08 firmware
v02.04 and earlier, and ACERA 9010-24 firmware v02.04 and earlier. An unauthenticated
attacker may log in to the product with no password, and obtain and/or
alter information such as network configuration and user information. The
products are affected only when running in non MS mode with the initial
configuration.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28744</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2021-47208</p>
</td>
<td rowspan="1" colspan="1">
<p>The Mojolicious module before 9.11 for Perl has a bug in format detection
that can potentially be exploited for denial of service.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2021-47208</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2020-36829</p>
</td>
<td rowspan="1" colspan="1">
<p>The Mojolicious module before 8.65 for Perl is vulnerable to secure_compare
timing attacks that allow an attacker to guess the length of a secret string.
Only versions after 1.74 are affected.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2020-36829</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31951</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Opaque LSA Extended Link parser in FRRouting (FRR) through 9.1,
there can be a buffer overflow and daemon crash in ospf_te_parse_ext_link
for OSPF LSA packets during an attempt to read Segment Routing Adjacency
SID subTLVs (lengths are not validated).</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31951</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31950</p>
</td>
<td rowspan="1" colspan="1">
<p>In FRRouting (FRR) through 9.1, there can be a buffer overflow and daemon
crash in ospf_te_parse_ri for OSPF LSA packets during an attempt to read
Segment Routing subTLVs (their size is not validated).</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31950</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31949</p>
</td>
<td rowspan="1" colspan="1">
<p>In FRRouting (FRR) through 9.1, an infinite loop can occur when receiving
a MP/GR capability as a dynamic capability because malformed data results
in a pointer not advancing.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31949</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31948</p>
</td>
<td rowspan="1" colspan="1">
<p>In FRRouting (FRR) through 9.1, an attacker using a malformed Prefix SID
attribute in a BGP UPDATE packet can cause the bgpd daemon to crash.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31948</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30418</p>
</td>
<td rowspan="1" colspan="1">
<p>Vulnerability of insufficient permission verification in the app management
module.
<br>Impact: Successful exploitation of this vulnerability will affect availability.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30418</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30417</p>
</td>
<td rowspan="1" colspan="1">
<p>Path traversal vulnerability in the Bluetooth-based sharing module.
<br>Impact: Successful exploitation of this vulnerability may affect service
confidentiality.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30417</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30416</p>
</td>
<td rowspan="1" colspan="1">
<p>Use After Free (UAF) vulnerability in the underlying driver module.
<br>Impact: Successful exploitation of this vulnerability will affect availability.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30416</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52717</p>
</td>
<td rowspan="1" colspan="1">
<p>Permission verification vulnerability in the lock screen module.
<br>Impact: Successful exploitation of this vulnerability will affect availability.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52717</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52716</p>
</td>
<td rowspan="1" colspan="1">
<p>Vulnerability of starting activities in the background in the ActivityManagerService
(AMS) module.
<br>Impact: Successful exploitation of this vulnerability will affect availability.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52716</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52715</p>
</td>
<td rowspan="1" colspan="1">
<p>The SystemUI module has a vulnerability in permission management.
<br>Impact: Successful exploitation of this vulnerability may affect availability.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52715</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52714</p>
</td>
<td rowspan="1" colspan="1">
<p>Vulnerability of defects introduced in the design process in the hwnff
module.
<br>Impact: Successful exploitation of this vulnerability may affect service
confidentiality.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52714</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52713</p>
</td>
<td rowspan="1" colspan="1">
<p>Vulnerability of improper permission control in the window management
module.
<br>Impact: Successful exploitation of this vulnerability will affect availability
and confidentiality.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52713</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52382</p>
</td>
<td rowspan="1" colspan="1">
<p>Vulnerability of improper control over foreground service notifications
in the notification module.
<br>Impact: Successful exploitation of this vulnerability may affect service
confidentiality.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52382</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30415</p>
</td>
<td rowspan="1" colspan="1">
<p>Vulnerability of improper permission control in the window management
module.
<br>Impact: Successful exploitation of this vulnerability will affect availability.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30415</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30414</p>
</td>
<td rowspan="1" colspan="1">
<p>Command injection vulnerability in the AccountManager module.
<br>Impact: Successful exploitation of this vulnerability may affect service
confidentiality.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30414</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30413</p>
</td>
<td rowspan="1" colspan="1">
<p>Vulnerability of improper permission control in the window management
module.
<br>Impact: Successful exploitation of this vulnerability will affect availability.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30413</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28741</p>
</td>
<td rowspan="1" colspan="1">
<p>Cross Site Scripting vulnerability in EginDemirbilek NorthStar C2 v1 allows
a remote attacker to execute arbitrary code via the login.php component.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28741</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27620</p>
</td>
<td rowspan="1" colspan="1">
<p>An issue in Ladder v.0.0.1 thru v.0.0.21 allows a remote attacker to obtain
sensitive information via a crafted request to the API.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27620</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3159</p>
</td>
<td rowspan="1" colspan="1">
<p>Out of bounds memory access in V8 in Google Chrome prior to 123.0.6312.105
allowed a remote attacker to perform arbitrary read/write via a crafted
HTML page. (Chromium security severity: High)</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3159</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3158</p>
</td>
<td rowspan="1" colspan="1">
<p>Use after free in Bookmarks in Google Chrome prior to 123.0.6312.105 allowed
a remote attacker to potentially exploit heap corruption via a crafted
HTML page. (Chromium security severity: High)</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3158</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-3156</p>
</td>
<td rowspan="1" colspan="1">
<p>Inappropriate implementation in V8 in Google Chrome prior to 123.0.6312.105
allowed a remote attacker to potentially perform out of bounds memory access
via a crafted HTML page. (Chromium security severity: High)</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-3156</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-24746</p>
</td>
<td rowspan="1" colspan="1">
<p>Loop with Unreachable Exit Condition ('Infinite Loop') vulnerability in
Apache NimBLE.&nbsp;
<br>
<br>Specially crafted GATT operation can cause infinite loop in GATT server
leading to denial of service in Bluetooth stack or device.
<br>
<br>This issue affects Apache NimBLE: through 1.6.0.
<br>Users are recommended to upgrade to version 1.7.0, which fixes the issue.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-24746</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2444</p>
</td>
<td rowspan="1" colspan="1">
<p>The Inline Related Posts WordPress plugin before 3.5.0 does not sanitise
and escape some of its settings, which could allow high privilege users
such as Admin to perform Cross-Site Scripting attacks even when unfiltered_html
is disallowed</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2444</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30977</p>
</td>
<td rowspan="1" colspan="1">
<p>An issue in Secnet Security Network Intelligent AC Management System v.1.02.040
allows a local attacker to escalate privileges via the password component.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30977</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29783</p>
</td>
<td rowspan="1" colspan="1">
<p>In tmu_get_tr_thresholds, there is a possible out of bounds read due to
a missing bounds check. This could lead to local information disclosure
with no additional execution privileges needed. User interaction is not
needed for exploitation.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29783</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29782</p>
</td>
<td rowspan="1" colspan="1">
<p>In tmu_get_tr_num_thresholds of tmu.c, there is a possible out of bounds
read due to a missing bounds check. This could lead to local information
disclosure with no additional execution privileges needed. User interaction
is not needed for exploitation.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29782</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29757</p>
</td>
<td rowspan="1" colspan="1">
<p>there is a possible permission bypass due to Debug certs being allowlisted.
This could lead to local escalation of privilege with no additional execution
privileges needed. User interaction is not needed for exploitation.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29757</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29756</p>
</td>
<td rowspan="1" colspan="1">
<p>In afe_callback of q6afe.c, there is a possible out of bounds write due
to a buffer overflow. This could lead to local escalation of privilege
with no additional execution privileges needed. User interaction is not
needed for exploitation.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29756</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29755</p>
</td>
<td rowspan="1" colspan="1">
<p>In tmu_get_pi of tmu.c, there is a possible out of bounds read due to
improper input validation. This could lead to local information disclosure
with no additional execution privileges needed. User interaction is not
needed for exploitation.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29755</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29754</p>
</td>
<td rowspan="1" colspan="1">
<p>In TMU_IPC_GET_TABLE, there is a possible out of bounds read due to a
missing bounds check. This could lead to local information disclosure with
no additional execution privileges needed. User interaction is not needed
for exploitation.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29754</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29753</p>
</td>
<td rowspan="1" colspan="1">
<p>In tmu_set_control_temp_step of tmu.c, there is a possible out of bounds
write due to a missing bounds check. This could lead to local escalation
of privilege with no additional execution privileges needed. User interaction
is not needed for exploitation.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29753</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29752</p>
</td>
<td rowspan="1" colspan="1">
<p>In tmu_set_tr_num_thresholds of tmu.c, there is a possible out of bounds
write due to a missing bounds check. This could lead to local escalation
of privilege with no additional execution privileges needed. User interaction
is not needed for exploitation.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29752</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29751</p>
</td>
<td rowspan="1" colspan="1">
<p>In asn1_ec_pkey_parse_p384 of asn1_common.c, there is a possible OOB Read
due to a missing null check. This could lead to local information disclosure
with no additional execution privileges needed. User interaction is not
needed for exploitation.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29751</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29750</p>
</td>
<td rowspan="1" colspan="1">
<p>In km_exp_did_inner of kmv.c, there is a possible out of bounds read due
to a missing bounds check. This could lead to local information disclosure
with no additional execution privileges needed. User interaction is not
needed for exploitation.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29750</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29749</p>
</td>
<td rowspan="1" colspan="1">
<p>In tmu_set_tr_thresholds of tmu.c, there is a possible out of bounds write
due to a missing bounds check. This could lead to local escalation of privilege
with no additional execution privileges needed. User interaction is not
needed for exploitation.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29749</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29747</p>
</td>
<td rowspan="1" colspan="1">
<p>In <em>dvfs</em>get_lv of dvfs.c, there is a possible out of bounds read
due to a missing null check. This could lead to local information disclosure
with no additional execution privileges needed. User interaction is not
needed for exploitation.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29747</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29746</p>
</td>
<td rowspan="1" colspan="1">
<p>In lpm_req_handler of lpm.c, there is a possible out of bounds write due
to improper input validation. This could lead to local escalation of privilege
with no additional execution privileges needed. User interaction is not
needed for exploitation.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29746</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29744</p>
</td>
<td rowspan="1" colspan="1">
<p>In tmu_get_gov_time_windows, there is a possible out of bounds read due
to a missing bounds check. This could lead to local information disclosure
with no additional execution privileges needed. User interaction is not
needed for exploitation.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29744</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29743</p>
</td>
<td rowspan="1" colspan="1">
<p>In tmu_set_temp_lut of tmu.c, there is a possible out of bounds write
due to a missing bounds check. This could lead to local escalation of privilege
with no additional execution privileges needed. User interaction is not
needed for exploitation.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29743</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29742</p>
</td>
<td rowspan="1" colspan="1">
<p>In apply_minlock_constraint of dvfs.c, there is a possible out of bounds
read due to a missing bounds check. This could lead to local information
disclosure with no additional execution privileges needed. User interaction
is not needed for exploitation.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29742</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29741</p>
</td>
<td rowspan="1" colspan="1">
<p>In pblS2mpuResume of s2mpu.c, there is a possible mitigation bypass due
to a logic error in the code. This could lead to local escalation of privilege
with no additional execution privileges needed. User interaction is not
needed for exploitation.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29741</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29740</p>
</td>
<td rowspan="1" colspan="1">
<p>In tmu_set_table of tmu.c, there is a possible out of bounds write due
to a missing bounds check. This could lead to local escalation of privilege
with no additional execution privileges needed. User interaction is not
needed for exploitation.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29740</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29739</p>
</td>
<td rowspan="1" colspan="1">
<p>In tmu_get_temp_lut of tmu.c, there is a possible out of bounds read due
to a missing bounds check. This could lead to local information disclosure
with no additional execution privileges needed. User interaction is not
needed for exploitation.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29739</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29738</p>
</td>
<td rowspan="1" colspan="1">
<p>In gov_init, there is a possible out of bounds read due to a missing bounds
check. This could lead to local information disclosure with no additional
execution privileges needed. User interaction is not needed for exploitation.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29738</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27232</p>
</td>
<td rowspan="1" colspan="1">
<p>In asn1_ec_pkey_parse of asn1_common.c, there is a possible OOB read due
to a missing null check. This could lead to local information disclosure
with no additional execution privileges needed. User interaction is not
needed for exploitation.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27232</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27231</p>
</td>
<td rowspan="1" colspan="1">
<p>In tmu_get_tr_stats of tmu.c, there is a possible out of bounds read due
to a missing bounds check. This could lead to local information disclosure
with no additional execution privileges needed. User interaction is not
needed for exploitation.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27231</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28065</p>
</td>
<td rowspan="1" colspan="1">
<p>In Unify CP IP Phone firmware 1.10.4.3, files are not encrypted and contain
sensitive information such as the root password hash.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28065</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31852</p>
</td>
<td rowspan="1" colspan="1">
<p>LLVM before 18.1.3 generates code in which the LR register can be overwritten
without data being saved to the stack, and thus there can sometimes be
an exploitable error in the flow of control. This affects the ARM backend
and can be demonstrated with Clang. NOTE: the vendor perspective is "we
don't have strong objections for a CVE to be created ... It does seem that
the likelihood of this miscompile enabling an exploit remains very low,
because the miscompile resulting in this JOP gadget is such that the function
is most likely to crash on most valid inputs to the function. So, if this
function is covered by any testing, the miscompile is most likely to be
discovered before the binary is shipped to production."</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31852</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-49965</p>
</td>
<td rowspan="1" colspan="1">
<p>SpaceX Starlink Wi-Fi router Gen 2 before 2023.48.0 allows XSS via the
ssid and password parameters on the Setup Page.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-49965</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27437</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>vfio/pci: Disable auto-enable of exclusive INTx IRQ
<br>
<br>Currently for devices requiring masking at the irqchip for INTx, ie.
<br>devices without DisINTx support, the IRQ is enabled in request_irq()
<br>and subsequently disabled as necessary to align with the masked status
<br>flag. This presents a window where the interrupt could fire between
<br>these events, resulting in the IRQ incrementing the disable depth twice.
<br>This would be unrecoverable for a user since the masked flag prevents
<br>nested enables through vfio.
<br>
<br>Instead, invert the logic using IRQF_NO_AUTOEN such that exclusive INTx
<br>is never auto-enabled, then unmask as required.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27437</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26814</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>vfio/fsl-mc: Block calling interrupt handler without trigger
<br>
<br>The eventfd_ctx trigger pointer of the vfio_fsl_mc_irq object is
<br>initially NULL and may become NULL if the user sets the trigger
<br>eventfd to -1. The interrupt handler itself is guaranteed that
<br>trigger is always valid between request_irq() and free_irq(), but
<br>the loopback testing mechanisms to invoke the handler function
<br>need to test the trigger. The triggering and setting ioctl paths
<br>both make use of igate and are therefore mutually exclusive.
<br>
<br>The vfio-fsl-mc driver does not make use of irqfds, nor does it
<br>support any sort of masking operations, therefore unlike vfio-pci
<br>and vfio-platform, the flow can remain essentially unchanged.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26814</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26813</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>vfio/platform: Create persistent IRQ handlers
<br>
<br>The vfio-platform SET_IRQS ioctl currently allows loopback triggering
of
<br>an interrupt before a signaling eventfd has been configured by the user,
<br>which thereby allows a NULL pointer dereference.
<br>
<br>Rather than register the IRQ relative to a valid trigger, register all
<br>IRQs in a disabled state in the device open path. This allows mask
<br>operations on the IRQ to nest within the overall enable state governed
<br>by a valid eventfd signal. This decouples @masked, protected by the
<br>@locked spinlock from @trigger, protected via the @igate mutex.
<br>
<br>In doing so, it's guaranteed that changes to @trigger cannot race the
<br>IRQ handlers because the IRQ handler is synchronously disabled before
<br>modifying the trigger, and loopback triggering of the IRQ via ioctl is
<br>safe due to serialization with trigger changes via igate.
<br>
<br>For compatibility, request_irq() failures are maintained to be local to
<br>the SET_IRQS ioctl rather than a fatal error in the open device path.
<br>This allows, for example, a userspace driver with polling mode support
<br>to continue to work regardless of moving the request_irq() call site.
<br>This necessarily blocks all SET_IRQS access to the failed index.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26813</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26812</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>vfio/pci: Create persistent INTx handler
<br>
<br>A vulnerability exists where the eventfd for INTx signaling can be
<br>deconfigured, which unregisters the IRQ handler but still allows
<br>eventfds to be signaled with a NULL context through the SET_IRQS ioctl
<br>or through unmask irqfd if the device interrupt is pending.
<br>
<br>Ideally this could be solved with some additional locking; the igate
<br>mutex serializes the ioctl and config space accesses, and the interrupt
<br>handler is unregistered relative to the trigger, but the irqfd path
<br>runs asynchronous to those. The igate mutex cannot be acquired from the
<br>atomic context of the eventfd wake function. Disabling the irqfd
<br>relative to the eventfd registration is potentially incompatible with
<br>existing userspace.
<br>
<br>As a result, the solution implemented here moves configuration of the
<br>INTx interrupt handler to track the lifetime of the INTx context object
<br>and irq_type configuration, rather than registration of a particular
<br>trigger eventfd. Synchronization is added between the ioctl path and
<br>eventfd_signal() wrapper such that the eventfd trigger can be
<br>dynamically updated relative to in-flight interrupts or irqfd callbacks.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26812</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26810</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>vfio/pci: Lock external INTx masking ops
<br>
<br>Mask operations through config space changes to DisINTx may race INTx
<br>configuration changes via ioctl. Create wrappers that add locking for
<br>paths outside of the core interrupt code.
<br>
<br>In particular, irq_type is updated holding igate, therefore testing
<br>is_intx() requires holding igate. For example clearing DisINTx from
<br>config space can otherwise race changes of the interrupt configuration.
<br>
<br>This aligns interfaces which may trigger the INTx eventfd into two
<br>camps, one side serialized by igate and the other only enabled while
<br>INTx is configured. A subsequent patch introduces synchronization for
<br>the latter flows.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26810</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30891</p>
</td>
<td rowspan="1" colspan="1">
<p>A command injection vulnerability exists in /goform/exeCommand in Tenda
AC18 v15.03.05.05, which allows attackers to construct cmdinput parameters
for arbitrary command execution.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30891</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30849</p>
</td>
<td rowspan="1" colspan="1">
<p>Arbitrary file upload vulnerability in Sourcecodester Complete E-Commerce
Site v1.0, allows remote attackers to execute arbitrary code via filename
parameter in admin/products_photo.php.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30849</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29863</p>
</td>
<td rowspan="1" colspan="1">
<p>A race condition in the installer executable in Qlik Qlikview before versions
May 2022 SR3 (12.70.20300) and May 2023 SR2 (12,80.20200) may allow an
existing lower privileged user to cause code to be executed in the context
of a Windows Administrator.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29863</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26329</p>
</td>
<td rowspan="1" colspan="1">
<p>Chilkat before v9.5.0.98, allows attackers to obtain sensitive information
via predictable PRNG in ChilkatRand::randomBytes function.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26329</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27448</p>
</td>
<td rowspan="1" colspan="1">
<p>MailDev 2 through 2.1.0 allows Remote Code Execution via a crafted Content-ID
header for an e-mail attachment, leading to lib/mailserver.js writing arbitrary
code into the routes.js file.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27448</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-22363</p>
</td>
<td rowspan="1" colspan="1">
<p>SheetJS Community Edition before 0.20.2 is <a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">vulnerable.to</a> Regular Expression Denial
of Service (ReDoS).</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-22363</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52235</p>
</td>
<td rowspan="1" colspan="1">
<p>SpaceX Starlink Wi-Fi router GEN 2 before 2023.53.0 and Starlink Dish
before 07dd2798-ff15-4722-a9ee-de28928aed34 allow CSRF (e.g., for a reboot)
via a DNS Rebinding attack.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52235</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2509</p>
</td>
<td rowspan="1" colspan="1">
<p>The Gutenberg Blocks by Kadence Blocks WordPress plugin before 3.2.26
does not validate and escape some of its block options before outputting
them back in a page/post where the block is embed, which could allow users
with the contributor role and above to perform Stored Cross-Site Scripting
attacks</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2509</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31498</p>
</td>
<td rowspan="1" colspan="1">
<p>Yubico ykman-gui (aka YubiKey Manager GUI) before 1.2.6 on Windows, when
Edge is not used, allows privilege escalation because browser windows can
open as Administrator.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31498</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27981</p>
</td>
<td rowspan="1" colspan="1">
<p>A Command Injection vulnerability found in a Self-Hosted UniFi Network
Servers (Linux) with UniFi Network Application (Version 8.0.28 and earlier)
allows a malicious actor with UniFi Network Application Administrator credentials
to escalate privileges to root on the host device.\r
<br>\r
<br>Affected Products:\r
<br>UniFi Network Application (Version 8.0.28 and earlier) .\r
<br>\r
<br>Mitigation:\r
<br>Update UniFi Network Application to Version 8.1.113 or later.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27981</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-45288</p>
</td>
<td rowspan="1" colspan="1">
<p>An attacker may cause an HTTP/2 endpoint to read arbitrary amounts of
header data by sending an excessive number of CONTINUATION frames. Maintaining
HPACK state requires parsing and processing all HEADERS and CONTINUATION
frames on a connection. When a request's headers exceed MaxHeaderBytes,
no memory is allocated to store the excess headers, but they are still
parsed. This permits an attacker to cause an HTTP/2 endpoint to read arbitrary
amounts of header data, all associated with a request which is going to
be rejected. These headers can include Huffman-encoded data which is significantly
more expensive for the receiver to decode than for an attacker to send.
The fix sets a limit on the amount of excess header frames we will process
before closing a connection.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-45288</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29387</p>
</td>
<td rowspan="1" colspan="1">
<p>projeqtor up to 11.2.0 was discovered to contain a remote code execution
(RCE) vulnerability via the component /view/print.php.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29387</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29386</p>
</td>
<td rowspan="1" colspan="1">
<p>projeqtor up to 11.2.0 was discovered to contain a SQL injection vulnerability
via the component /view/criticalResourceExport.php.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29386</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27316</p>
</td>
<td rowspan="1" colspan="1">
<p>HTTP/2 incoming headers exceeding the limit are temporarily buffered in
nghttp2 in order to generate an informative HTTP 413 response. If a client
does not stop sending headers, this leads to memory exhaustion.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27316</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-24795</p>
</td>
<td rowspan="1" colspan="1">
<p>HTTP Response splitting in multiple modules in Apache HTTP Server allows
an attacker that can inject malicious response headers into backend applications
to cause an HTTP desynchronization attack.
<br>
<br>Users are recommended to upgrade to version 2.4.59, which fixes this issue.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-24795</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-38709</p>
</td>
<td rowspan="1" colspan="1">
<p>Faulty input validation in the core of Apache allows malicious or exploitable
backend/content generators to split HTTP responses.
<br>
<br>This issue affects Apache HTTP Server: through 2.4.58.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-38709</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2759</p>
</td>
<td rowspan="1" colspan="1">
<p>Improper access control vulnerability in Apaczka plugin for PrestaShop
allows information gathering from saved templates without authentication.This
issue affects Apaczka plugin for PrestaShop from v1 through v4.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2759</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27575</p>
</td>
<td rowspan="1" colspan="1">
<p>INOTEC Sicherheitstechnik WebServer CPS220/64 3.3.19 allows a remote attacker
to read arbitrary files via absolute path traversal, such as with the /cgi-bin/display?file=/etc/passwd
URI.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27575</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26809</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>netfilter: nft_set_pipapo: release elements in clone only from destroy
path
<br>
<br>Clone already always provides a current view of the lookup table, use
it
<br>to destroy the set, otherwise it is possible to destroy elements twice.
<br>
<br>This fix requires:
<br>
<br>212ed75dc5fb ("netfilter: nf_tables: integrate pipapo into commit protocol")
<br>
<br>which came after:
<br>
<br>9827a0e6e23b ("netfilter: nft_set_pipapo: release elements in clone from
abort path").</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26809</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26808</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>netfilter: nft_chain_filter: handle NETDEV_UNREGISTER for inet/ingress
basechain
<br>
<br>Remove netdevice from inet/ingress basechain in case NETDEV_UNREGISTER
<br>event is reported, otherwise a stale reference to netdevice remains in
<br>the hook list.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26808</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26807</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>spi: cadence-qspi: fix pointer reference in runtime PM hooks
<br>
<br>dev_get_drvdata() gets used to acquire the pointer to cqspi and the SPI
<br>controller. Neither embed the other; this lead to memory corruption.
<br>
<br>On a given platform (Mobileye EyeQ5) the memory corruption is hidden
<br>inside cqspi-&gt;f_pdata. Also, this uninitialised memory is used as a
<br>mutex (ctlr-&gt;bus_lock_mutex) by spi_controller_suspend().</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26807</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26806</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>spi: cadence-qspi: remove system-wide suspend helper calls from runtime
PM hooks
<br>
<br>The -&gt;runtime_suspend() and -&gt;runtime_resume() callbacks are not
<br>expected to call spi_controller_suspend() and spi_controller_resume().
<br>Remove calls to those in the cadence-qspi driver.
<br>
<br>Those helpers have two roles currently:
<br>- They stop/start the queue, including dealing with the kworker.
<br>- They toggle the SPI controller SPI_CONTROLLER_SUSPENDED flag. It
<br>requires acquiring ctlr-&gt;bus_lock_mutex.
<br>
<br>Step one is irrelevant because cadence-qspi is not queued. Step two
<br>however has two implications:
<br>- A deadlock occurs, because -&gt;runtime_resume() is called in a context
<br>where the lock is already taken (in the -&gt;exec_op() callback, where
<br>the usage count is incremented).
<br>- It would disallow all operations once the device is auto-suspended.
<br>
<br>Here is a brief call tree highlighting the mutex deadlock:
<br>
<br>spi_mem_exec_op()
<br>...
<br>spi_mem_access_start()
<br>mutex_lock(&amp;ctlr-&gt;bus_lock_mutex)
<br>
<br>cqspi_exec_mem_op()
<br>pm_runtime_resume_and_get()
<br>cqspi_resume()
<br>spi_controller_resume()
<br>mutex_lock(&amp;ctlr-&gt;bus_lock_mutex)
<br>...
<br>
<br>spi_mem_access_end()
<br>mutex_unlock(&amp;ctlr-&gt;bus_lock_mutex)
<br>...</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26806</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26805</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>netlink: Fix kernel-infoleak-after-free in __skb_datagram_iter
<br>
<br>syzbot reported the following uninit-value access issue [1]:
<br>
<br>netlink_to_full_skb() creates a new <code>skb</code> and puts the <code>skb-&gt;data</code>
<br>passed as a 1st arg of netlink_to_full_skb() onto new <code>skb</code>.
The data
<br>size is specified as <code>len</code> and passed to skb_put_data(). This <code>len</code>
<br>is based on <code>skb-&gt;end</code> that is not data offset but buffer
offset. The
<br>`skb-&gt;end` contains data and tailroom. Since the tailroom is not
<br>initialized when the new <code>skb</code> created, KMSAN detects uninitialized
<br>memory area when copying the data.
<br>
<br>This patch resolved this issue by correct the len from <code>skb-&gt;end</code> to
<br>`skb-&gt;len`, which is the actual data offset.
<br>
<br>BUG: KMSAN: kernel-infoleak-after-free in instrument_copy_to_user include/linux/instrumented.h:114
[inline]
<br>BUG: KMSAN: kernel-infoleak-after-free in copy_to_user_iter lib/iov_iter.c:24
[inline]
<br>BUG: KMSAN: kernel-infoleak-after-free in iterate_ubuf include/linux/iov_iter.h:29
[inline]
<br>BUG: KMSAN: kernel-infoleak-after-free in iterate_and_advance2 include/linux/iov_iter.h:245
[inline]
<br>BUG: KMSAN: kernel-infoleak-after-free in iterate_and_advance include/linux/iov_iter.h:271
[inline]
<br>BUG: KMSAN: kernel-infoleak-after-free in <em>copy</em>to_iter+0x364/0x2520
lib/iov_iter.c:186
<br>instrument_copy_to_user include/linux/instrumented.h:114 [inline]
<br>copy_to_user_iter lib/iov_iter.c:24 [inline]
<br>iterate_ubuf include/linux/iov_iter.h:29 [inline]
<br>iterate_and_advance2 include/linux/iov_iter.h:245 [inline]
<br>iterate_and_advance include/linux/iov_iter.h:271 [inline]
<br>_copy_to_iter+0x364/0x2520 lib/iov_iter.c:186
<br>copy_to_iter include/linux/uio.h:197 [inline]
<br>simple_copy_to_iter+0x68/0xa0 net/core/datagram.c:532
<br>__skb_datagram_iter+0x123/0xdc0 net/core/datagram.c:420
<br>skb_copy_datagram_iter+0x5c/0x200 net/core/datagram.c:546
<br>skb_copy_datagram_msg include/linux/skbuff.h:3960 [inline]
<br>packet_recvmsg+0xd9c/0x2000 net/packet/af_packet.c:3482
<br>sock_recvmsg_nosec net/socket.c:1044 [inline]
<br>sock_recvmsg net/socket.c:1066 [inline]
<br>sock_read_iter+0x467/0x580 net/socket.c:1136
<br>call_read_iter include/linux/fs.h:2014 [inline]
<br>new_sync_read fs/read_write.c:389 [inline]
<br>vfs_read+0x8f6/0xe00 fs/read_write.c:470
<br>ksys_read+0x20f/0x4c0 fs/read_write.c:613
<br>__do_sys_read fs/read_write.c:623 [inline]
<br>__se_sys_read fs/read_write.c:621 [inline]
<br>__x64_sys_read+0x93/0xd0 fs/read_write.c:621
<br>do_syscall_x64 arch/x86/entry/common.c:52 [inline]
<br>do_syscall_64+0x44/0x110 arch/x86/entry/common.c:83
<br>entry_SYSCALL_64_after_hwframe+0x63/0x6b
<br>
<br>Uninit was stored to memory at:
<br>skb_put_data include/linux/skbuff.h:2622 [inline]
<br>netlink_to_full_skb net/netlink/af_netlink.c:181 [inline]
<br>__netlink_deliver_tap_skb net/netlink/af_netlink.c:298 [inline]
<br>__netlink_deliver_tap+0x5be/0xc90 net/netlink/af_netlink.c:325
<br>netlink_deliver_tap net/netlink/af_netlink.c:338 [inline]
<br>netlink_deliver_tap_kernel net/netlink/af_netlink.c:347 [inline]
<br>netlink_unicast_kernel net/netlink/af_netlink.c:1341 [inline]
<br>netlink_unicast+0x10f1/0x1250 net/netlink/af_netlink.c:1368
<br>netlink_sendmsg+0x1238/0x13d0 net/netlink/af_netlink.c:1910
<br>sock_sendmsg_nosec net/socket.c:730 [inline]
<br>__sock_sendmsg net/socket.c:745 [inline]
<br>____sys_sendmsg+0x9c2/0xd60 net/socket.c:2584
<br>___sys_sendmsg+0x28d/0x3c0 net/socket.c:2638
<br>__sys_sendmsg net/socket.c:2667 [inline]
<br>__do_sys_sendmsg net/socket.c:2676 [inline]
<br>__se_sys_sendmsg net/socket.c:2674 [inline]
<br>__x64_sys_sendmsg+0x307/0x490 net/socket.c:2674
<br>do_syscall_x64 arch/x86/entry/common.c:52 [inline]
<br>do_syscall_64+0x44/0x110 arch/x86/entry/common.c:83
<br>entry_SYSCALL_64_after_hwframe+0x63/0x6b
<br>
<br>Uninit was created at:
<br>free_pages_prepare mm/page_alloc.c:1087 [inline]
<br>free_unref_page_prepare+0xb0/0xa40 mm/page_alloc.c:2347
<br>free_unref_page_list+0xeb/0x1100 mm/page_alloc.c:2533
<br>release_pages+0x23d3/0x2410 mm/swap.c:1042
<br>free_pages_and_swap_cache+0xd9/0xf0 mm/swap_state.c:316
<br>tlb_batch_pages
<br>---truncated---</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26805</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26804</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>net: ip_tunnel: prevent perpetual headroom growth
<br>
<br>syzkaller triggered following kasan splat:
<br>BUG: KASAN: use-after-free in __skb_flow_dissect+0x19d1/0x7a50 net/core/flow_dissector.c:1170
<br>Read of size 1 at addr ffff88812fb4000e by task syz-executor183/5191
<br>[..]
<br>kasan_report+0xda/0x110 mm/kasan/report.c:588
<br>__skb_flow_dissect+0x19d1/0x7a50 net/core/flow_dissector.c:1170
<br>skb_flow_dissect_flow_keys include/linux/skbuff.h:1514 [inline]
<br>___skb_get_hash net/core/flow_dissector.c:1791 [inline]
<br>__skb_get_hash+0xc7/0x540 net/core/flow_dissector.c:1856
<br>skb_get_hash include/linux/skbuff.h:1556 [inline]
<br>ip_tunnel_xmit+0x1855/0x33c0 net/ipv4/ip_tunnel.c:748
<br>ipip_tunnel_xmit+0x3cc/0x4e0 net/ipv4/ipip.c:308
<br>__netdev_start_xmit include/linux/netdevice.h:4940 [inline]
<br>netdev_start_xmit include/linux/netdevice.h:4954 [inline]
<br>xmit_one net/core/dev.c:3548 [inline]
<br>dev_hard_start_xmit+0x13d/0x6d0 net/core/dev.c:3564
<br>__dev_queue_xmit+0x7c1/0x3d60 net/core/dev.c:4349
<br>dev_queue_xmit include/linux/netdevice.h:3134 [inline]
<br>neigh_connected_output+0x42c/0x5d0 net/core/neighbour.c:1592
<br>...
<br>ip_finish_output2+0x833/0x2550 net/ipv4/ip_output.c:235
<br>ip_finish_output+0x31/0x310 net/ipv4/ip_output.c:323
<br>..
<br>iptunnel_xmit+0x5b4/0x9b0 net/ipv4/ip_tunnel_core.c:82
<br>ip_tunnel_xmit+0x1dbc/0x33c0 net/ipv4/ip_tunnel.c:831
<br>ipgre_xmit+0x4a1/0x980 net/ipv4/ip_gre.c:665
<br>__netdev_start_xmit include/linux/netdevice.h:4940 [inline]
<br>netdev_start_xmit include/linux/netdevice.h:4954 [inline]
<br>xmit_one net/core/dev.c:3548 [inline]
<br>dev_hard_start_xmit+0x13d/0x6d0 net/core/dev.c:3564
<br>...
<br>
<br>The splat occurs because skb-&gt;data points past skb-&gt;head allocated
area.
<br>This is because neigh layer does:
<br>__skb_pull(skb, skb_network_offset(skb));
<br>
<br>... but skb_network_offset() returns a negative offset and __skb_pull()
<br>arg is unsigned. IOW, we skb-&gt;data gets "adjusted" by a huge value.
<br>
<br>The negative value is returned because skb-&gt;head and skb-&gt;data distance
is
<br>more than 64k and skb-&gt;network_header (u16) has wrapped around.
<br>
<br>The bug is in the ip_tunnel infrastructure, which can cause
<br>dev-&gt;needed_headroom to increment ad infinitum.
<br>
<br>The syzkaller reproducer consists of packets getting routed via a gre
<br>tunnel, and route of gre encapsulated packets pointing at another (ipip)
<br>tunnel. The ipip encapsulation finds gre0 as next output device.
<br>
<br>This results in the following pattern:
<br>
<br>1). First packet is to be sent out via gre0.
<br>Route lookup found an output device, ipip0.
<br>
<br>2).
<br>ip_tunnel_xmit for gre0 bumps gre0-&gt;needed_headroom based on the future
<br>output device, <a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">rt.dev</a>-&gt;needed_headroom
(ipip0).
<br>
<br>3).
<br>ip output / start_xmit moves skb on to ipip0. which runs the same
<br>code path again (xmit recursion).
<br>
<br>4).
<br>Routing step for the post-gre0-encap packet finds gre0 as output device
<br>to use for ipip0 encapsulated packet.
<br>
<br>tunl0-&gt;needed_headroom is then incremented based on the (already bumped)
<br>gre0 device headroom.
<br>
<br>This repeats for every future packet:
<br>
<br>gre0-&gt;needed_headroom gets inflated because previous packets' ipip0
step
<br>incremented rt-&gt;dev (gre0) headroom, and ipip0 incremented because
gre0
<br>needed_headroom was increased.
<br>
<br>For each subsequent packet, gre/ipip0-&gt;needed_headroom grows until
<br>post-expand-head reallocations result in a skb-&gt;head/data distance
of
<br>more than 64k.
<br>
<br>Once that happens, skb-&gt;network_header (u16) wraps around when
<br>pskb_expand_head tries to make sure that skb_network_offset() is unchanged
<br>after the headroom expansion/reallocation.
<br>
<br>After this skb_network_offset(skb) returns a different (and negative)
<br>result post headroom expansion.
<br>
<br>The next trip to neigh layer (or anything else that would __skb_pull the
<br>network header) makes skb-&gt;data point to a memory location outside
<br>skb-&gt;head area.
<br>
<br>v2: Cap the needed_headroom update to an arbitarily chosen upperlimit
to
<br>prevent perpetual increase instead of dropping the headroom increment
<br>completely.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26804</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26803</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>net: veth: clear GRO when clearing XDP even when down
<br>
<br>veth sets NETIF_F_GRO automatically when XDP is enabled,
<br>because both features use the same NAPI machinery.
<br>
<br>The logic to clear NETIF_F_GRO sits in veth_disable_xdp() which
<br>is called both on ndo_stop and when XDP is turned off.
<br>To avoid the flag from being cleared when the device is brought
<br>down, the clearing is skipped when IFF_UP is not set.
<br>Bringing the device down should indeed not modify its features.
<br>
<br>Unfortunately, this means that clearing is also skipped when
<br>XDP is disabled <em>while</em> the device is down. And there's nothing
<br>on the open path to bring the device features back into sync.
<br>IOW if user enables XDP, disables it and then brings the device
<br>up we'll end up with a stray GRO flag set but no NAPI instances.
<br>
<br>We don't depend on the GRO flag on the datapath, so the datapath
<br>won't crash. We will crash (or hang), however, next time features
<br>are sync'ed (either by user via ethtool or peer changing its config).
<br>The GRO flag will go away, and veth will try to disable the NAPIs.
<br>But the open path never created them since XDP was off, the GRO flag
<br>was a stray. If NAPI was initialized before we'll hang in napi_disable().
<br>If it never was we'll crash trying to stop uninitialized hrtimer.
<br>
<br>Move the GRO flag updates to the XDP enable / disable paths,
<br>instead of mixing them with the ndo_open / ndo_close paths.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26803</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26802</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>stmmac: Clear variable when destroying workqueue
<br>
<br>Currently when suspending driver and stopping workqueue it is checked
whether
<br>workqueue is not NULL and if so, it is destroyed.
<br>Function destroy_workqueue() does drain queue and does clear variable,
but
<br>it does not set workqueue variable to NULL. This can cause kernel/module
<br>panic if code attempts to clear workqueue that was not initialized.
<br>
<br>This scenario is possible when resuming suspended driver in stmmac_resume(),
<br>because there is no handling for failed stmmac_hw_setup(),
<br>which can fail and return if DMA engine has failed to initialize,
<br>and workqueue is initialized after DMA engine.
<br>Should DMA engine fail to initialize, resume will proceed normally,
<br>but interface won't work and TX queue will eventually timeout,
<br>causing 'Reset adapter' error.
<br>This then does destroy workqueue during reset process.
<br>And since workqueue is initialized after DMA engine and can be skipped,
<br>it will cause kernel/module panic.
<br>
<br>To secure against this possible crash, set workqueue variable to NULL
when
<br>destroying workqueue.
<br>
<br>Log/backtrace from crash goes as follows:
<br>[88.031977]------------[ cut here ]------------
<br>[88.031985]NETDEV WATCHDOG: eth0 (sxgmac): transmit queue 1 timed out
<br>[88.032017]WARNING: CPU: 0 PID: 0 at net/sched/sch_generic.c:477 dev_watchdog+0x390/0x398
<br>&lt;Skipping backtrace for watchdog timeout&gt;
<br>[88.032251]---[ end trace e70de432e4d5c2c0 ]---
<br>[88.032282]sxgmac 16d88000.ethernet eth0: Reset adapter.
<br>[88.036359]------------[ cut here ]------------
<br>[88.036519]Call trace:
<br>[88.036523] flush_workqueue+0x3e4/0x430
<br>[88.036528] drain_workqueue+0xc4/0x160
<br>[88.036533] destroy_workqueue+0x40/0x270
<br>[88.036537] stmmac_fpe_stop_wq+0x4c/0x70
<br>[88.036541] stmmac_release+0x278/0x280
<br>[88.036546] __dev_close_many+0xcc/0x158
<br>[88.036551] dev_close_many+0xbc/0x190
<br>[88.036555] dev_close.part.0+0x70/0xc0
<br>[88.036560] dev_close+0x24/0x30
<br>[88.036564] stmmac_service_task+0x110/0x140
<br>[88.036569] process_one_work+0x1d8/0x4a0
<br>[88.036573] worker_thread+0x54/0x408
<br>[88.036578] kthread+0x164/0x170
<br>[88.036583] ret_from_fork+0x10/0x20
<br>[88.036588]---[ end trace e70de432e4d5c2c1 ]---
<br>[88.036597]Unable to handle kernel NULL pointer dereference at virtual
address 0000000000000004</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26802</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26801</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>Bluetooth: Avoid potential use-after-free in hci_error_reset
<br>
<br>While handling the HCI_EV_HARDWARE_ERROR event, if the underlying
<br>BT controller is not responding, the GPIO reset mechanism would
<br>free the hci_dev and lead to a use-after-free in hci_error_reset.
<br>
<br>Here's the call trace observed on a ChromeOS device with Intel AX201:
<br>queue_work_on+0x3e/0x6c
<br>__hci_cmd_sync_sk+0x2ee/0x4c0 [bluetooth &lt;HASH:3b4a6&gt;]
<br>? init_wait_entry+0x31/0x31
<br>__hci_cmd_sync+0x16/0x20 [bluetooth &lt;HASH:3b4a 6&gt;]
<br>hci_error_reset+0x4f/0xa4 [bluetooth &lt;HASH:3b4a 6&gt;]
<br>process_one_work+0x1d8/0x33f
<br>worker_thread+0x21b/0x373
<br>kthread+0x13a/0x152
<br>? pr_cont_work+0x54/0x54
<br>? kthread_blkcg+0x31/0x31
<br>ret_from_fork+0x1f/0x30
<br>
<br>This patch holds the reference count on the hci_dev while processing
<br>a HCI_EV_HARDWARE_ERROR event to avoid potential crash.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26801</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26800</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>tls: fix use-after-free on failed backlog decryption
<br>
<br>When the decrypt request goes to the backlog and crypto_aead_decrypt
<br>returns -EBUSY, tls_do_decryption will wait until all async
<br>decryptions have completed. If one of them fails, tls_do_decryption
<br>will return -EBADMSG and tls_decrypt_sg jumps to the error path,
<br>releasing all the pages. But the pages have been passed to the async
<br>callback, and have already been released by tls_decrypt_done.
<br>
<br>The only true async case is when crypto_aead_decrypt returns
<br>-EINPROGRESS. With -EBUSY, we already waited so we can tell
<br>tls_sw_recvmsg that the data is available for immediate copy, but we
<br>need to notify tls_decrypt_sg (via the new -&gt;async_done flag) that
the
<br>memory has already been released.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26800</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26799</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>ASoC: qcom: Fix uninitialized pointer dmactl
<br>
<br>In the case where __lpass_get_dmactl_handle is called and the driver
<br>id dai_id is invalid the pointer dmactl is not being assigned a value,
<br>and dmactl contains a garbage value since it has not been initialized
<br>and so the null check may not work. Fix this to initialize dmactl to
<br>NULL. One could argue that modern compilers will set this to zero, but
<br>it is useful to keep this initialized as per the same way in functions
<br>__lpass_platform_codec_intf_init and lpass_cdc_dma_daiops_hw_params.
<br>
<br>Cleans up clang scan build warning:
<br>sound/soc/qcom/lpass-cdc-dma.c:275:7: warning: Branch condition
<br>evaluates to a garbage value [core.uninitialized.Branch]</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26799</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26798</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>fbcon: always restore the old font data in fbcon_do_set_font()
<br>
<br>Commit a5a923038d70 (fbdev: fbcon: Properly revert changes when
<br>vc_resize() failed) started restoring old font data upon failure (of
<br>vc_resize()). But it performs so only for user fonts. It means that the
<br>"system"/internal fonts are not restored at all. So in result, the very
<br>first call to fbcon_do_set_font() performs no restore at all upon
<br>failing vc_resize().
<br>
<br>This can be reproduced by Syzkaller to crash the system on the next
<br>invocation of font_get(). It's rather hard to hit the allocation failure
<br>in vc_resize() on the first font_set(), but not impossible. Esp. if
<br>fault injection is used to aid the execution/failure. It was
<br>demonstrated by Sirius:
<br>BUG: unable to handle page fault for address: fffffffffffffff8
<br>#PF: supervisor read access in kernel mode
<br>#PF: error_code(0x0000) - not-present page
<br>PGD cb7b067 P4D cb7b067 PUD cb7d067 PMD 0
<br>Oops: 0000 [#1] PREEMPT SMP KASAN
<br>CPU: 1 PID: 8007 Comm: poc Not tainted 6.7.0-g9d1694dc91ce #20
<br>Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
<br>RIP: 0010:fbcon_get_font+0x229/0x800 drivers/video/fbdev/core/fbcon.c:2286
<br>Call Trace:
<br>&lt;TASK&gt;
<br>con_font_get drivers/tty/vt/vt.c:4558 [inline]
<br>con_font_op+0x1fc/0xf20 drivers/tty/vt/vt.c:4673
<br>vt_k_ioctl drivers/tty/vt/vt_ioctl.c:474 [inline]
<br>vt_ioctl+0x632/0x2ec0 drivers/tty/vt/vt_ioctl.c:752
<br>tty_ioctl+0x6f8/0x1570 drivers/tty/tty_io.c:2803
<br>vfs_ioctl fs/ioctl.c:51 [inline]
<br>...
<br>
<br>So restore the font data in any case, not only for user fonts. Note the
<br>later 'if' is now protected by 'old_userfont' and not 'old_data' as the
<br>latter is always set now. (And it is supposed to be non-NULL. Otherwise
<br>we would see the bug above again.)</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26798</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26797</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>drm/amd/display: Prevent potential buffer overflow in map_hw_resources
<br>
<br>Adds a check in the map_hw_resources function to prevent a potential
<br>buffer overflow. The function was accessing arrays using an index that
<br>could potentially be greater than the size of the arrays, leading to a
<br>buffer overflow.
<br>
<br>Adds a check to ensure that the index is within the bounds of the
<br>arrays. If the index is out of bounds, an error message is printed and
<br>break it will continue execution with just ignoring extra data early to
<br>prevent the buffer overflow.
<br>
<br>Reported by smatch:
<br>drivers/gpu/drm/amd/amdgpu/../display/dc/dml2/dml2_wrapper.c:79 map_hw_resources()
error: buffer overflow 'dml2-&gt;v20.scratch.dml_to_dc_pipe_mapping.disp_cfg_to_stream_id'
6 &lt;= 7
<br>drivers/gpu/drm/amd/amdgpu/../display/dc/dml2/dml2_wrapper.c:81 map_hw_resources()
error: buffer overflow 'dml2-&gt;v20.scratch.dml_to_dc_pipe_mapping.disp_cfg_to_plane_id'
6 &lt;= 7</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26797</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26796</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>drivers: perf: ctr_get_width function for legacy is not defined
<br>
<br>With parameters CONFIG_RISCV_PMU_LEGACY=y and CONFIG_RISCV_PMU_SBI=n
<br>linux kernel crashes when you try perf record:
<br>
<br>$ perf record ls
<br>[ 46.749286] Unable to handle kernel NULL pointer dereference at virtual
address 0000000000000000
<br>[ 46.750199] Oops [#1]
<br>[ 46.750342] Modules linked in:
<br>[ 46.750608] CPU: 0 PID: 107 Comm: perf-exec Not tainted 6.6.0 #2
<br>[ 46.750906] Hardware name: riscv-virtio,qemu (DT)
<br>[ 46.751184] epc : 0x0
<br>[ 46.751430] ra : arch_perf_update_userpage+0x54/0x13e
<br>[ 46.751680] epc : 0000000000000000 ra : ffffffff8072ee52 sp : ff2000000022b8f0
<br>[ 46.751958] gp : ffffffff81505988 tp : ff6000000290d400 t0 : ff2000000022b9c0
<br>[ 46.752229] t1 : 0000000000000001 t2 : 0000000000000003 s0 : ff2000000022b930
<br>[ 46.752451] s1 : ff600000028fb000 a0 : 0000000000000000 a1 : ff600000028fb000
<br>[ 46.752673] a2 : 0000000ae2751268 a3 : 00000000004fb708 a4 : 0000000000000004
<br>[ 46.752895] a5 : 0000000000000000 a6 : 000000000017ffe3 a7 : 00000000000000d2
<br>[ 46.753117] s2 : ff600000028fb000 s3 : 0000000ae2751268 s4 : 0000000000000000
<br>[ 46.753338] s5 : ffffffff8153e290 s6 : ff600000863b9000 s7 : ff60000002961078
<br>[ 46.753562] s8 : ff60000002961048 s9 : ff60000002961058 s10: 0000000000000001
<br>[ 46.753783] s11: 0000000000000018 t3 : ffffffffffffffff t4 : ffffffffffffffff
<br>[ 46.754005] t5 : ff6000000292270c t6 : ff2000000022bb30
<br>[ 46.754179] status: 0000000200000100 badaddr: 0000000000000000 cause:
000000000000000c
<br>[ 46.754653] Code: Unable to access instruction at 0xffffffffffffffec.
<br>[ 46.754939] ---[ end trace 0000000000000000 ]---
<br>[ 46.755131] note: perf-exec[107] exited with irqs disabled
<br>[ 46.755546] note: perf-exec[107] exited with preempt_count 4
<br>
<br>This happens because in the legacy case the ctr_get_width function was
not
<br>defined, but it is used in arch_perf_update_userpage.
<br>
<br>Also remove extra check in riscv_pmu_ctr_get_width_mask</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26796</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26795</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>riscv: Sparse-Memory/vmemmap out-of-bounds fix
<br>
<br>Offset vmemmap so that the first page of vmemmap will be mapped
<br>to the first page of physical memory in order to ensure that
<br>vmemmap’s bounds will be respected during
<br>pfn_to_page()/page_to_pfn() operations.
<br>The conversion macros will produce correct SV39/48/57 addresses
<br>for every possible/valid DRAM_BASE inside the physical memory limits.
<br>
<br>v2:Address Alex's comments</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26795</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26794</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>btrfs: fix race between ordered extent completion and fiemap
<br>
<br>For fiemap we recently stopped locking the target extent range for the
<br>whole duration of the fiemap call, in order to avoid a deadlock in a
<br>scenario where the fiemap buffer happens to be a memory mapped range of
<br>the same file. This use case is very unlikely to be useful in practice
but
<br>it may be triggered by fuzz testing (syzbot, etc).
<br>
<br>However by not locking the target extent range for the whole duration
of
<br>the fiemap call we can race with an ordered extent. This happens like
<br>this:
<br>
<br>1) The fiemap task finishes processing a file extent item that covers
<br>the file range [512K, 1M[, and that file extent item is the last item
<br>in the leaf currently being processed;
<br>
<br>2) And ordered extent for the file range [768K, 2M[, in COW mode,
<br>completes (btrfs_finish_one_ordered()) and the file extent item
<br>covering the range [512K, 1M[ is trimmed to cover the range
<br>[512K, 768K[ and then a new file extent item for the range [768K, 2M[
<br>is inserted in the inode's subvolume tree;
<br>
<br>3) The fiemap task calls fiemap_next_leaf_item(), which then calls
<br>btrfs_next_leaf() to find the next leaf / item. This finds that the
<br>the next key following the one we previously processed (its type is
<br>BTRFS_EXTENT_DATA_KEY and its offset is 512K), is the key corresponding
<br>to the new file extent item inserted by the ordered extent, which has
<br>a type of BTRFS_EXTENT_DATA_KEY and an offset of 768K;
<br>
<br>4) Later the fiemap code ends up at emit_fiemap_extent() and triggers
<br>the warning:
<br>
<br>if (cache-&gt;offset + cache-&gt;len &gt; offset) {
<br>WARN_ON(1);
<br>return -EINVAL;
<br>}
<br>
<br>Since we get 1M &gt; 768K, because the previously emitted entry for the
<br>old extent covering the file range [512K, 1M[ ends at an offset that
<br>is greater than the new extent's start offset (768K). This makes fiemap
<br>fail with -EINVAL besides triggering the warning that produces a stack
<br>trace like the following:
<br>
<br>[1621.677651] ------------[ cut here ]------------
<br>[1621.677656] WARNING: CPU: 1 PID: 204366 at fs/btrfs/extent_io.c:2492
emit_fiemap_extent+0x84/0x90 [btrfs]
<br>[1621.677899] Modules linked in: btrfs blake2b_generic (...)
<br>[1621.677951] CPU: 1 PID: 204366 Comm: pool Not tainted 6.8.0-rc5-btrfs-next-151+
#1
<br>[1621.677954] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS
<a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">rel-1.16.2-0-gea1b7a073390-prebuilt.qemu.org</a>04/01/2014
<br>[1621.677956] RIP: 0010:emit_fiemap_extent+0x84/0x90 [btrfs]
<br>[1621.678033] Code: 2b 4c 89 63 (...)
<br>[1621.678035] RSP: 0018:ffffab16089ffd20 EFLAGS: 00010206
<br>[1621.678037] RAX: 00000000004fa000 RBX: ffffab16089ffe08 RCX: 0000000000009000
<br>[1621.678039] RDX: 00000000004f9000 RSI: 00000000004f1000 RDI: ffffab16089ffe90
<br>[1621.678040] RBP: 00000000004f9000 R08: 0000000000001000 R09: 0000000000000000
<br>[1621.678041] R10: 0000000000000000 R11: 0000000000001000 R12: 0000000041d78000
<br>[1621.678043] R13: 0000000000001000 R14: 0000000000000000 R15: ffff9434f0b17850
<br>[1621.678044] FS: 00007fa6e20006c0(0000) GS:ffff943bdfa40000(0000) knlGS:0000000000000000
<br>[1621.678046] CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033
<br>[1621.678048] CR2: 00007fa6b0801000 CR3: 000000012d404002 CR4: 0000000000370ef0
<br>[1621.678053] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
<br>[1621.678055] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
<br>[1621.678056] Call Trace:
<br>[1621.678074] &lt;TASK&gt;
<br>[1621.678076] ? __warn+0x80/0x130
<br>[1621.678082] ? emit_fiemap_extent+0x84/0x90 [btrfs]
<br>[1621.678159] ? report_bug+0x1f4/0x200
<br>[1621.678164] ? handle_bug+0x42/0x70
<br>[1621.678167] ? exc_invalid_op+0x14/0x70
<br>[1621.678170] ? asm_exc_invalid_op+0x16/0x20
<br>[1621.678178] ? emit_fiemap_extent+0x84/0x90 [btrfs]
<br>[1621.678253] extent_fiemap+0x766
<br>---truncated---</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26794</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26793</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>gtp: fix use-after-free and null-ptr-deref in gtp_newlink()
<br>
<br>The gtp_link_ops operations structure for the subsystem must be
<br>registered after registering the gtp_net_ops pernet operations structure.
<br>
<br>Syzkaller hit 'general protection fault in gtp_genl_dump_pdp' bug:
<br>
<br>[ 1010.702740] gtp: GTP module unloaded
<br>[ 1010.715877] general protection fault, probably for non-canonical address
0xdffffc0000000001: 0000 [#1] SMP KASAN NOPTI
<br>[ 1010.715888] KASAN: null-ptr-deref in range [0x0000000000000008-0x000000000000000f]
<br>[ 1010.715895] CPU: 1 PID: 128616 Comm: a.out Not tainted 6.8.0-rc6-std-def-alt1
#1
<br>[ 1010.715899] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS
1.16.0-alt1 04/01/2014
<br>[ 1010.715908] RIP: 0010:gtp_newlink+0x4d7/0x9c0 [gtp]
<br>[ 1010.715915] Code: 80 3c 02 00 0f 85 41 04 00 00 48 8b bb d8 05 00 00
e8 ed f6 ff ff 48 89 c2 48 89 c5 48 b8 00 00 00 00 00 fc ff df 48 c1 ea
03 &lt;80&gt; 3c 02 00 0f 85 4f 04 00 00 4c 89 e2 4c 8b 6d 00 48 b8 00
00 00
<br>[ 1010.715920] RSP: 0018:ffff888020fbf180 EFLAGS: 00010203
<br>[ 1010.715929] RAX: dffffc0000000000 RBX: ffff88800399c000 RCX: 0000000000000000
<br>[ 1010.715933] RDX: 0000000000000001 RSI: ffffffff84805280 RDI: 0000000000000282
<br>[ 1010.715938] RBP: 000000000000000d R08: 0000000000000001 R09: 0000000000000000
<br>[ 1010.715942] R10: 0000000000000001 R11: 0000000000000001 R12: ffff88800399cc80
<br>[ 1010.715947] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000400
<br>[ 1010.715953] FS: 00007fd1509ab5c0(0000) GS:ffff88805b300000(0000) knlGS:0000000000000000
<br>[ 1010.715958] CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033
<br>[ 1010.715962] CR2: 0000000000000000 CR3: 000000001c07a000 CR4: 0000000000750ee0
<br>[ 1010.715968] PKRU: 55555554
<br>[ 1010.715972] Call Trace:
<br>[ 1010.715985] ? __die_body.cold+0x1a/0x1f
<br>[ 1010.715995] ? die_addr+0x43/0x70
<br>[ 1010.716002] ? exc_general_protection+0x199/0x2f0
<br>[ 1010.716016] ? asm_exc_general_protection+0x1e/0x30
<br>[ 1010.716026] ? gtp_newlink+0x4d7/0x9c0 [gtp]
<br>[ 1010.716034] ? gtp_net_exit+0x150/0x150 [gtp]
<br>[ 1010.716042] __rtnl_newlink+0x1063/0x1700
<br>[ 1010.716051] ? rtnl_setlink+0x3c0/0x3c0
<br>[ 1010.716063] ? is_bpf_text_address+0xc0/0x1f0
<br>[ 1010.716070] ? kernel_text_address.part.0+0xbb/0xd0
<br>[ 1010.716076] ? __kernel_text_address+0x56/0xa0
<br>[ 1010.716084] ? unwind_get_return_address+0x5a/0xa0
<br>[ 1010.716091] ? create_prof_cpu_mask+0x30/0x30
<br>[ 1010.716098] ? arch_stack_walk+0x9e/0xf0
<br>[ 1010.716106] ? stack_trace_save+0x91/0xd0
<br>[ 1010.716113] ? stack_trace_consume_entry+0x170/0x170
<br>[ 1010.716121] ? __lock_acquire+0x15c5/0x5380
<br>[ 1010.716139] ? mark_held_locks+0x9e/0xe0
<br>[ 1010.716148] ? kmem_cache_alloc_trace+0x35f/0x3c0
<br>[ 1010.716155] ? __rtnl_newlink+0x1700/0x1700
<br>[ 1010.716160] rtnl_newlink+0x69/0xa0
<br>[ 1010.716166] rtnetlink_rcv_msg+0x43b/0xc50
<br>[ 1010.716172] ? rtnl_fdb_dump+0x9f0/0x9f0
<br>[ 1010.716179] ? lock_acquire+0x1fe/0x560
<br>[ 1010.716188] ? netlink_deliver_tap+0x12f/0xd50
<br>[ 1010.716196] netlink_rcv_skb+0x14d/0x440
<br>[ 1010.716202] ? rtnl_fdb_dump+0x9f0/0x9f0
<br>[ 1010.716208] ? netlink_ack+0xab0/0xab0
<br>[ 1010.716213] ? netlink_deliver_tap+0x202/0xd50
<br>[ 1010.716220] ? netlink_deliver_tap+0x218/0xd50
<br>[ 1010.716226] ? __virt_addr_valid+0x30b/0x590
<br>[ 1010.716233] netlink_unicast+0x54b/0x800
<br>[ 1010.716240] ? netlink_attachskb+0x870/0x870
<br>[ 1010.716248] ? __check_object_size+0x2de/0x3b0
<br>[ 1010.716254] netlink_sendmsg+0x938/0xe40
<br>[ 1010.716261] ? netlink_unicast+0x800/0x800
<br>[ 1010.716269] ? __import_iovec+0x292/0x510
<br>[ 1010.716276] ? netlink_unicast+0x800/0x800
<br>[ 1010.716284] __sock_sendmsg+0x159/0x190
<br>[ 1010.716290] ____sys_sendmsg+0x712/0x880
<br>[ 1010.716297] ? sock_write_iter+0x3d0/0x3d0
<br>[ 1010.716304] ? __ia32_sys_recvmmsg+0x270/0x270
<br>[ 1010.716309] ? lock_acquire+0x1fe/0x560
<br>[ 1010.716315] ? drain_array_locked+0x90/0x90
<br>[ 1010.716324] ___sys_sendmsg+0xf8/0x170
<br>[ 1010.716331] ? sendmsg_copy_msghdr+0x170/0x170
<br>[ 1010.716337] ? lockdep_init_map
<br>---truncated---</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26793</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26792</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>btrfs: fix double free of anonymous device after snapshot creation failure
<br>
<br>When creating a snapshot we may do a double free of an anonymous device
<br>in case there's an error committing the transaction. The second free may
<br>result in freeing an anonymous device number that was allocated by some
<br>other subsystem in the kernel or another btrfs filesystem.
<br>
<br>The steps that lead to this:
<br>
<br>1) At ioctl.c:create_snapshot() we allocate an anonymous device number
<br>and assign it to pending_snapshot-&gt;anon_dev;
<br>
<br>2) Then we call btrfs_commit_transaction() and end up at
<br>transaction.c:create_pending_snapshot();
<br>
<br>3) There we call btrfs_get_new_fs_root() and pass it the anonymous device
<br>number stored in pending_snapshot-&gt;anon_dev;
<br>
<br>4) btrfs_get_new_fs_root() frees that anonymous device number because
<br>btrfs_lookup_fs_root() returned a root - someone else did a lookup
<br>of the new root already, which could some task doing backref walking;
<br>
<br>5) After that some error happens in the transaction commit path, and at
<br>ioctl.c:create_snapshot() we jump to the 'fail' label, and after
<br>that we free again the same anonymous device number, which in the
<br>meanwhile may have been reallocated somewhere else, because
<br>pending_snapshot-&gt;anon_dev still has the same value as in step 1.
<br>
<br>Recently syzbot ran into this and reported the following trace:
<br>
<br>------------[ cut here ]------------
<br>ida_free called for id=51 which is not allocated.
<br>WARNING: CPU: 1 PID: 31038 at lib/idr.c:525 ida_free+0x370/0x420 lib/idr.c:525
<br>Modules linked in:
<br>CPU: 1 PID: 31038 Comm: syz-executor.2 Not tainted 6.8.0-rc4-syzkaller-00410-gc02197fc9076
#0
<br>Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS
Google 01/25/2024
<br>RIP: 0010:ida_free+0x370/0x420 lib/idr.c:525
<br>Code: 10 42 80 3c 28 (...)
<br>RSP: 0018:ffffc90015a67300 EFLAGS: 00010246
<br>RAX: be5130472f5dd000 RBX: 0000000000000033 RCX: 0000000000040000
<br>RDX: ffffc90009a7a000 RSI: 000000000003ffff RDI: 0000000000040000
<br>RBP: ffffc90015a673f0 R08: ffffffff81577992 R09: 1ffff92002b4cdb4
<br>R10: dffffc0000000000 R11: fffff52002b4cdb5 R12: 0000000000000246
<br>R13: dffffc0000000000 R14: ffffffff8e256b80 R15: 0000000000000246
<br>FS: 00007fca3f4b46c0(0000) GS:ffff8880b9500000(0000) knlGS:0000000000000000
<br>CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033
<br>CR2: 00007f167a17b978 CR3: 000000001ed26000 CR4: 0000000000350ef0
<br>Call Trace:
<br>&lt;TASK&gt;
<br>btrfs_get_root_ref+0xa48/0xaf0 fs/btrfs/disk-io.c:1346
<br>create_pending_snapshot+0xff2/0x2bc0 fs/btrfs/transaction.c:1837
<br>create_pending_snapshots+0x195/0x1d0 fs/btrfs/transaction.c:1931
<br>btrfs_commit_transaction+0xf1c/0x3740 fs/btrfs/transaction.c:2404
<br>create_snapshot+0x507/0x880 fs/btrfs/ioctl.c:848
<br>btrfs_mksubvol+0x5d0/0x750 fs/btrfs/ioctl.c:998
<br>btrfs_mksnapshot+0xb5/0xf0 fs/btrfs/ioctl.c:1044
<br>__btrfs_ioctl_snap_create+0x387/0x4b0 fs/btrfs/ioctl.c:1306
<br>btrfs_ioctl_snap_create_v2+0x1ca/0x400 fs/btrfs/ioctl.c:1393
<br>btrfs_ioctl+0xa74/0xd40
<br>vfs_ioctl fs/ioctl.c:51 [inline]
<br>__do_sys_ioctl fs/ioctl.c:871 [inline]
<br>__se_sys_ioctl+0xfe/0x170 fs/ioctl.c:857
<br>do_syscall_64+0xfb/0x240
<br>entry_SYSCALL_64_after_hwframe+0x6f/0x77
<br>RIP: 0033:0x7fca3e67dda9
<br>Code: 28 00 00 00 (...)
<br>RSP: 002b:00007fca3f4b40c8 EFLAGS: 00000246 ORIG_RAX: 0000000000000010
<br>RAX: ffffffffffffffda RBX: 00007fca3e7abf80 RCX: 00007fca3e67dda9
<br>RDX: 00000000200005c0 RSI: 0000000050009417 RDI: 0000000000000003
<br>RBP: 00007fca3e6ca47a R08: 0000000000000000 R09: 0000000000000000
<br>R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000
<br>R13: 000000000000000b R14: 00007fca3e7abf80 R15: 00007fff6bf95658
<br>&lt;/TASK&gt;
<br>
<br>Where we get an explicit message where we attempt to free an anonymous
<br>device number that is not currently allocated. It happens in a different
<br>code path from the example below, at btrfs_get_root_ref(), so this change
<br>may not fix the case triggered by sy
<br>---truncated---</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26792</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26791</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>btrfs: dev-replace: properly validate device names
<br>
<br>There's a syzbot report that device name buffers passed to device
<br>replace are not properly checked for string termination which could lead
<br>to a read out of bounds in getname_kernel().
<br>
<br>Add a helper that validates both source and target device name buffers.
<br>For devid as the source initialize the buffer to empty string in case
<br>something tries to read it later.
<br>
<br>This was originally analyzed and fixed in a different way by Edward Adam
<br>Davis (see links).</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26791</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26790</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>dmaengine: fsl-qdma: fix SoC may hang on 16 byte unaligned read
<br>
<br>There is chip (ls1028a) errata:
<br>
<br>The SoC may hang on 16 byte unaligned read transactions by QDMA.
<br>
<br>Unaligned read transactions initiated by QDMA may stall in the NOC
<br>(Network On-Chip), causing a deadlock condition. Stalled transactions
will
<br>trigger completion timeouts in PCIe controller.
<br>
<br>Workaround:
<br>Enable prefetch by setting the source descriptor prefetchable bit
<br>( SD[PF] = 1 ).
<br>
<br>Implement this workaround.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26790</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26789</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>crypto: arm64/neonbs - fix out-of-bounds access on short input
<br>
<br>The bit-sliced implementation of AES-CTR operates on blocks of 128
<br>bytes, and will fall back to the plain NEON version for tail blocks or
<br>inputs that are shorter than 128 bytes to begin with.
<br>
<br>It will call straight into the plain NEON asm helper, which performs all
<br>memory accesses in granules of 16 bytes (the size of a NEON register).
<br>For this reason, the associated plain NEON glue code will copy inputs
<br>shorter than 16 bytes into a temporary buffer, given that this is a rare
<br>occurrence and it is not worth the effort to work around this in the asm
<br>code.
<br>
<br>The fallback from the bit-sliced NEON version fails to take this into
<br>account, potentially resulting in out-of-bounds accesses. So clone the
<br>same workaround, and use a temp buffer for short in/outputs.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26789</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26788</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>dmaengine: fsl-qdma: init irq after reg initialization
<br>
<br>Initialize the qDMA irqs after the registers are configured so that
<br>interrupts that may have been pending from a primary kernel don't get
<br>processed by the irq handler before it is ready to and cause panic with
<br>the following trace:
<br>
<br>Call trace:
<br>fsl_qdma_queue_handler+0xf8/0x3e8
<br>__handle_irq_event_percpu+0x78/0x2b0
<br>handle_irq_event_percpu+0x1c/0x68
<br>handle_irq_event+0x44/0x78
<br>handle_fasteoi_irq+0xc8/0x178
<br>generic_handle_irq+0x24/0x38
<br>__handle_domain_irq+0x90/0x100
<br>gic_handle_irq+0x5c/0xb8
<br>el1_irq+0xb8/0x180
<br>_raw_spin_unlock_irqrestore+0x14/0x40
<br>__setup_irq+0x4bc/0x798
<br>request_threaded_irq+0xd8/0x190
<br>devm_request_threaded_irq+0x74/0xe8
<br>fsl_qdma_probe+0x4d4/0xca8
<br>platform_drv_probe+0x50/0xa0
<br>really_probe+0xe0/0x3f8
<br>driver_probe_device+0x64/0x130
<br>device_driver_attach+0x6c/0x78
<br>__driver_attach+0xbc/0x158
<br>bus_for_each_dev+0x5c/0x98
<br>driver_attach+0x20/0x28
<br>bus_add_driver+0x158/0x220
<br>driver_register+0x60/0x110
<br>__platform_driver_register+0x44/0x50
<br>fsl_qdma_driver_init+0x18/0x20
<br>do_one_initcall+0x48/0x258
<br>kernel_init_freeable+0x1a4/0x23c
<br>kernel_init+0x10/0xf8
<br>ret_from_fork+0x10/0x18</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26788</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26787</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>mmc: mmci: stm32: fix DMA API overlapping mappings warning
<br>
<br>Turning on CONFIG_DMA_API_DEBUG_SG results in the following warning:
<br>
<br>DMA-API: mmci-pl18x 48220000.mmc: cacheline tracking EEXIST,
<br>overlapping mappings aren't supported
<br>WARNING: CPU: 1 PID: 51 at kernel/dma/debug.c:568
<br>add_dma_entry+0x234/0x2f4
<br>Modules linked in:
<br>CPU: 1 PID: 51 Comm: kworker/1:2 Not tainted 6.1.28 #1
<br>Hardware name: STMicroelectronics STM32MP257F-EV1 Evaluation Board (DT)
<br>Workqueue: events_freezable mmc_rescan
<br>Call trace:
<br>add_dma_entry+0x234/0x2f4
<br>debug_dma_map_sg+0x198/0x350
<br>__dma_map_sg_attrs+0xa0/0x110
<br>dma_map_sg_attrs+0x10/0x2c
<br>sdmmc_idma_prep_data+0x80/0xc0
<br>mmci_prep_data+0x38/0x84
<br>mmci_start_data+0x108/0x2dc
<br>mmci_request+0xe4/0x190
<br>__mmc_start_request+0x68/0x140
<br>mmc_start_request+0x94/0xc0
<br>mmc_wait_for_req+0x70/0x100
<br>mmc_send_tuning+0x108/0x1ac
<br>sdmmc_execute_tuning+0x14c/0x210
<br>mmc_execute_tuning+0x48/0xec
<br>mmc_sd_init_uhs_card.part.0+0x208/0x464
<br>mmc_sd_init_card+0x318/0x89c
<br>mmc_attach_sd+0xe4/0x180
<br>mmc_rescan+0x244/0x320
<br>
<br>DMA API debug brings to light leaking dma-mappings as dma_map_sg and
<br>dma_unmap_sg are not correctly balanced.
<br>
<br>If an error occurs in mmci_cmd_irq function, only mmci_dma_error
<br>function is called and as this API is not managed on stm32 variant,
<br>dma_unmap_sg is never called in this error path.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26787</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26786</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>iommufd: Fix iopt_access_list_id overwrite bug
<br>
<br>Syzkaller reported the following WARN_ON:
<br>WARNING: CPU: 1 PID: 4738 at drivers/iommu/iommufd/io_pagetable.c:1360
<br>
<br>Call Trace:
<br>iommufd_access_change_ioas+0x2fe/0x4e0
<br>iommufd_access_destroy_object+0x50/0xb0
<br>iommufd_object_remove+0x2a3/0x490
<br>iommufd_object_destroy_user
<br>iommufd_access_destroy+0x71/0xb0
<br>iommufd_test_staccess_release+0x89/0xd0
<br>__fput+0x272/0xb50
<br>__fput_sync+0x4b/0x60
<br>__do_sys_close
<br>__se_sys_close
<br>__x64_sys_close+0x8b/0x110
<br>do_syscall_x64
<br>
<br>The mismatch between the access pointer in the list and the passed-in
<br>pointer is resulting from an overwrite of access-&gt;iopt_access_list_id,
in
<br>iopt_add_access(). Called from iommufd_access_change_ioas() when
<br>xa_alloc() succeeds but iopt_calculate_iova_alignment() fails.
<br>
<br>Add a new_id in iopt_add_access() and only update iopt_access_list_id
when
<br>returning successfully.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26786</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26785</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>iommufd: Fix protection fault in iommufd_test_syz_conv_iova
<br>
<br>Syzkaller reported the following bug:
<br>
<br>general protection fault, probably for non-canonical address 0xdffffc0000000038:
0000 [#1] SMP KASAN
<br>KASAN: null-ptr-deref in range [0x00000000000001c0-0x00000000000001c7]
<br>Call Trace:
<br>lock_acquire
<br>lock_acquire+0x1ce/0x4f0
<br>down_read+0x93/0x4a0
<br>iommufd_test_syz_conv_iova+0x56/0x1f0
<br>iommufd_test_access_rw.isra.0+0x2ec/0x390
<br>iommufd_test+0x1058/0x1e30
<br>iommufd_fops_ioctl+0x381/0x510
<br>vfs_ioctl
<br>__do_sys_ioctl
<br>__se_sys_ioctl
<br>__x64_sys_ioctl+0x170/0x1e0
<br>do_syscall_x64
<br>do_syscall_64+0x71/0x140
<br>
<br>This is because the new iommufd_access_change_ioas() sets access-&gt;ioas
to
<br>NULL during its process, so the lock might be gone in a concurrent racing
<br>context.
<br>
<br>Fix this by doing the same access-&gt;ioas sanity as iommufd_access_rw()
and
<br>iommufd_access_pin_pages() functions do.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26785</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26784</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>pmdomain: arm: Fix NULL dereference on scmi_perf_domain removal
<br>
<br>On unloading of the scmi_perf_domain module got the below splat, when
in
<br>the DT provided to the system under test the '#power-domain-cells' property
<br>was missing. Indeed, this particular setup causes the probe to bail out
<br>early without giving any error, which leads to the -&gt;remove() callback
gets
<br>to run too, but without all the expected initialized structures in place.
<br>
<br>Add a check and bail out early on remove too.
<br>
<br>Call trace:
<br>scmi_perf_domain_remove+0x28/0x70 [scmi_perf_domain]
<br>scmi_dev_remove+0x28/0x40 [scmi_core]
<br>device_remove+0x54/0x90
<br>device_release_driver_internal+0x1dc/0x240
<br>driver_detach+0x58/0xa8
<br>bus_remove_driver+0x78/0x108
<br>driver_unregister+0x38/0x70
<br>scmi_driver_unregister+0x28/0x180 [scmi_core]
<br>scmi_perf_domain_driver_exit+0x18/0xb78 [scmi_perf_domain]
<br>__arm64_sys_delete_module+0x1a8/0x2c0
<br>invoke_syscall+0x50/0x128
<br>el0_svc_common.constprop.0+0x48/0xf0
<br>do_el0_svc+0x24/0x38
<br>el0_svc+0x34/0xb8
<br>el0t_64_sync_handler+0x100/0x130
<br>el0t_64_sync+0x190/0x198
<br>Code: a90153f3 f9403c14 f9414800 955f8a05 (b9400a80)
<br>---[ end trace 0000000000000000 ]---</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26784</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26783</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>mm/vmscan: fix a bug calling wakeup_kswapd() with a wrong zone index
<br>
<br>With numa balancing on, when a numa system is running where a numa node
<br>doesn't have its local memory so it has no managed zones, the following
<br>oops has been observed. It's because wakeup_kswapd() is called with a
<br>wrong zone index, -1. Fixed it by checking the index before calling
<br>wakeup_kswapd().
<br>
<br>&gt; BUG: unable to handle page fault for address: 00000000000033f3
<br>&gt; #PF: supervisor read access in kernel mode
<br>&gt; #PF: error_code(0x0000) - not-present page
<br>&gt; PGD 0 P4D 0
<br>&gt; Oops: 0000 [#1] PREEMPT SMP NOPTI
<br>&gt; CPU: 2 PID: 895 Comm: masim Not tainted 6.6.0-dirty #255
<br>&gt; Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS
<br>&gt; <a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">rel-1.16.0-0-gd239552ce722-prebuilt.qemu.org</a> 04/01/2014
<br>&gt; RIP: 0010:wakeup_kswapd (./linux/mm/vmscan.c:7812)
<br>&gt; Code: (omitted)
<br>&gt; RSP: 0000:ffffc90004257d58 EFLAGS: 00010286
<br>&gt; RAX: ffffffffffffffff RBX: ffff88883fff0480 RCX: 0000000000000003
<br>&gt; RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffff88883fff0480
<br>&gt; RBP: ffffffffffffffff R08: ff0003ffffffffff R09: ffffffffffffffff
<br>&gt; R10: ffff888106c95540 R11: 0000000055555554 R12: 0000000000000003
<br>&gt; R13: 0000000000000000 R14: 0000000000000000 R15: ffff88883fff0940
<br>&gt; FS: 00007fc4b8124740(0000) GS:ffff888827c00000(0000) knlGS:0000000000000000
<br>&gt; CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033
<br>&gt; CR2: 00000000000033f3 CR3: 000000026cc08004 CR4: 0000000000770ee0
<br>&gt; DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
<br>&gt; DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
<br>&gt; PKRU: 55555554
<br>&gt; Call Trace:
<br>&gt; &lt;TASK&gt;
<br>&gt; ? __die
<br>&gt; ? page_fault_oops
<br>&gt; ? __pte_offset_map_lock
<br>&gt; ? exc_page_fault
<br>&gt; ? asm_exc_page_fault
<br>&gt; ? wakeup_kswapd
<br>&gt; migrate_misplaced_page
<br>&gt; __handle_mm_fault
<br>&gt; handle_mm_fault
<br>&gt; do_user_addr_fault
<br>&gt; exc_page_fault
<br>&gt; asm_exc_page_fault
<br>&gt; RIP: 0033:0x55b897ba0808
<br>&gt; Code: (omitted)
<br>&gt; RSP: 002b:00007ffeefa821a0 EFLAGS: 00010287
<br>&gt; RAX: 000055b89983acd0 RBX: 00007ffeefa823f8 RCX: 000055b89983acd0
<br>&gt; RDX: 00007fc2f8122010 RSI: 0000000000020000 RDI: 000055b89983acd0
<br>&gt; RBP: 00007ffeefa821a0 R08: 0000000000000037 R09: 0000000000000075
<br>&gt; R10: 0000000000000000 R11: 0000000000000202 R12: 0000000000000000
<br>&gt; R13: 00007ffeefa82410 R14: 000055b897ba5dd8 R15: 00007fc4b8340000
<br>&gt; &lt;/TASK&gt;</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26783</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26782</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>mptcp: fix double-free on socket dismantle
<br>
<br>when MPTCP server accepts an incoming connection, it clones its listener
<br>socket. However, the pointer to 'inet_opt' for the new socket has the
same
<br>value as the original one: as a consequence, on program exit it's possible
<br>to observe the following splat:
<br>
<br>BUG: KASAN: double-free in inet_sock_destruct+0x54f/0x8b0
<br>Free of addr ffff888485950880 by task swapper/25/0
<br>
<br>CPU: 25 PID: 0 Comm: swapper/25 Kdump: loaded Not tainted 6.8.0-rc1+ #609
<br>Hardware name: Supermicro SYS-6027R-72RF/X9DRH-7TF/7F/iTF/iF, BIOS 3.0
07/26/2013
<br>Call Trace:
<br>&lt;IRQ&gt;
<br>dump_stack_lvl+0x32/0x50
<br>print_report+0xca/0x620
<br>kasan_report_invalid_free+0x64/0x90
<br>__kasan_slab_free+0x1aa/0x1f0
<br>kfree+0xed/0x2e0
<br>inet_sock_destruct+0x54f/0x8b0
<br>__sk_destruct+0x48/0x5b0
<br>rcu_do_batch+0x34e/0xd90
<br>rcu_core+0x559/0xac0
<br>__do_softirq+0x183/0x5a4
<br>irq_exit_rcu+0x12d/0x170
<br>sysvec_apic_timer_interrupt+0x6b/0x80
<br>&lt;/IRQ&gt;
<br>&lt;TASK&gt;
<br>asm_sysvec_apic_timer_interrupt+0x16/0x20
<br>RIP: 0010:cpuidle_enter_state+0x175/0x300
<br>Code: 30 00 0f 84 1f 01 00 00 83 e8 01 83 f8 ff 75 e5 48 83 c4 18 44 89
e8 5b 5d 41 5c 41 5d 41 5e 41 5f c3 cc cc cc cc fb 45 85 ed &lt;0f&gt;
89 60 ff ff ff 48 c1 e5 06 48 c7 43 18 00 00 00 00 48 83 44 2b
<br>RSP: 0018:ffff888481cf7d90 EFLAGS: 00000202
<br>RAX: 0000000000000000 RBX: ffff88887facddc8 RCX: 0000000000000000
<br>RDX: 1ffff1110ff588b1 RSI: 0000000000000019 RDI: ffff88887fac4588
<br>RBP: 0000000000000004 R08: 0000000000000002 R09: 0000000000043080
<br>R10: 0009b02ea273363f R11: ffff88887fabf42b R12: ffffffff932592e0
<br>R13: 0000000000000004 R14: 0000000000000000 R15: 00000022c880ec80
<br>cpuidle_enter+0x4a/0xa0
<br>do_idle+0x310/0x410
<br>cpu_startup_entry+0x51/0x60
<br>start_secondary+0x211/0x270
<br>secondary_startup_64_no_verify+0x184/0x18b
<br>&lt;/TASK&gt;
<br>
<br>Allocated by task 6853:
<br>kasan_save_stack+0x1c/0x40
<br>kasan_save_track+0x10/0x30
<br>__kasan_kmalloc+0xa6/0xb0
<br>__kmalloc+0x1eb/0x450
<br>cipso_v4_sock_setattr+0x96/0x360
<br>netlbl_sock_setattr+0x132/0x1f0
<br>selinux_netlbl_socket_post_create+0x6c/0x110
<br>selinux_socket_post_create+0x37b/0x7f0
<br>security_socket_post_create+0x63/0xb0
<br>__sock_create+0x305/0x450
<br>__sys_socket_create.part.23+0xbd/0x130
<br>__sys_socket+0x37/0xb0
<br>__x64_sys_socket+0x6f/0xb0
<br>do_syscall_64+0x83/0x160
<br>entry_SYSCALL_64_after_hwframe+0x6e/0x76
<br>
<br>Freed by task 6858:
<br>kasan_save_stack+0x1c/0x40
<br>kasan_save_track+0x10/0x30
<br>kasan_save_free_info+0x3b/0x60
<br>__kasan_slab_free+0x12c/0x1f0
<br>kfree+0xed/0x2e0
<br>inet_sock_destruct+0x54f/0x8b0
<br>__sk_destruct+0x48/0x5b0
<br>subflow_ulp_release+0x1f0/0x250
<br>tcp_cleanup_ulp+0x6e/0x110
<br>tcp_v4_destroy_sock+0x5a/0x3a0
<br>inet_csk_destroy_sock+0x135/0x390
<br>tcp_fin+0x416/0x5c0
<br>tcp_data_queue+0x1bc8/0x4310
<br>tcp_rcv_state_process+0x15a3/0x47b0
<br>tcp_v4_do_rcv+0x2c1/0x990
<br>tcp_v4_rcv+0x41fb/0x5ed0
<br>ip_protocol_deliver_rcu+0x6d/0x9f0
<br>ip_local_deliver_finish+0x278/0x360
<br>ip_local_deliver+0x182/0x2c0
<br>ip_rcv+0xb5/0x1c0
<br>__netif_receive_skb_one_core+0x16e/0x1b0
<br>process_backlog+0x1e3/0x650
<br>__napi_poll+0xa6/0x500
<br>net_rx_action+0x740/0xbb0
<br>__do_softirq+0x183/0x5a4
<br>
<br>The buggy address belongs to the object at ffff888485950880
<br>which belongs to the cache kmalloc-64 of size 64
<br>The buggy address is located 0 bytes inside of
<br>64-byte region [ffff888485950880, ffff8884859508c0)
<br>
<br>The buggy address belongs to the physical page:
<br>page:0000000056d1e95e refcount:1 mapcount:0 mapping:0000000000000000 index:0xffff888485950700
pfn:0x485950
<br>flags: 0x57ffffc0000800(slab|node=1|zone=2|lastcpupid=0x1fffff)
<br>page_type: 0xffffffff()
<br>raw: 0057ffffc0000800 ffff88810004c640 ffffea00121b8ac0 dead000000000006
<br>raw: ffff888485950700 0000000000200019 00000001ffffffff 0000000000000000
<br>page dumped because: kasan: bad access detected
<br>
<br>Memory state around the buggy address:
<br>ffff888485950780: fa fb fb
<br>---truncated---</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26782</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26781</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>mptcp: fix possible deadlock in subflow diag
<br>
<br>Syzbot and Eric reported a lockdep splat in the subflow diag:
<br>
<br>WARNING: possible circular locking dependency detected
<br>6.8.0-rc4-syzkaller-00212-g40b9385dd8e6 #0 Not tainted
<br>
<br>syz-executor.2/24141 is trying to acquire lock:
<br>ffff888045870130 (k-sk_lock-AF_INET6){+.+.}-{0:0}, at:
<br>tcp_diag_put_ulp net/ipv4/tcp_diag.c:100 [inline]
<br>ffff888045870130 (k-sk_lock-AF_INET6){+.+.}-{0:0}, at:
<br>tcp_diag_get_aux+0x738/0x830 net/ipv4/tcp_diag.c:137
<br>
<br>but task is already holding lock:
<br>ffffc9000135e488 (&amp;h-&gt;lhash2[i].lock){+.+.}-{2:2}, at: spin_lock
<br>include/linux/spinlock.h:351 [inline]
<br>ffffc9000135e488 (&amp;h-&gt;lhash2[i].lock){+.+.}-{2:2}, at:
<br>inet_diag_dump_icsk+0x39f/0x1f80 net/ipv4/inet_diag.c:1038
<br>
<br>which lock already depends on the new lock.
<br>
<br>the existing dependency chain (in reverse order) is:
<br>
<br>-&gt; #1 (&amp;h-&gt;lhash2[i].lock){+.+.}-{2:2}:
<br>lock_acquire+0x1e3/0x530 kernel/locking/lockdep.c:5754
<br>__raw_spin_lock include/linux/spinlock_api_smp.h:133 [inline]
<br>_raw_spin_lock+0x2e/0x40 kernel/locking/spinlock.c:154
<br>spin_lock include/linux/spinlock.h:351 [inline]
<br>__inet_hash+0x335/0xbe0 net/ipv4/inet_hashtables.c:743
<br>inet_csk_listen_start+0x23a/0x320 net/ipv4/inet_connection_sock.c:1261
<br>__inet_listen_sk+0x2a2/0x770 net/ipv4/af_inet.c:217
<br>inet_listen+0xa3/0x110 net/ipv4/af_inet.c:239
<br>rds_tcp_listen_init+0x3fd/0x5a0 net/rds/tcp_listen.c:316
<br>rds_tcp_init_net+0x141/0x320 net/rds/tcp.c:577
<br>ops_init+0x352/0x610 net/core/net_namespace.c:136
<br>__register_pernet_operations net/core/net_namespace.c:1214 [inline]
<br>register_pernet_operations+0x2cb/0x660 net/core/net_namespace.c:1283
<br>register_pernet_device+0x33/0x80 net/core/net_namespace.c:1370
<br>rds_tcp_init+0x62/0xd0 net/rds/tcp.c:735
<br>do_one_initcall+0x238/0x830 init/main.c:1236
<br>do_initcall_level+0x157/0x210 init/main.c:1298
<br>do_initcalls+0x3f/0x80 init/main.c:1314
<br>kernel_init_freeable+0x42f/0x5d0 init/main.c:1551
<br>kernel_init+0x1d/0x2a0 init/main.c:1441
<br>ret_from_fork+0x4b/0x80 arch/x86/kernel/process.c:147
<br>ret_from_fork_asm+0x1b/0x30 arch/x86/entry/entry_64.S:242
<br>
<br>-&gt; #0 (k-sk_lock-AF_INET6){+.+.}-{0:0}:
<br>check_prev_add kernel/locking/lockdep.c:3134 [inline]
<br>check_prevs_add kernel/locking/lockdep.c:3253 [inline]
<br>validate_chain+0x18ca/0x58e0 kernel/locking/lockdep.c:3869
<br>__lock_acquire+0x1345/0x1fd0 kernel/locking/lockdep.c:5137
<br>lock_acquire+0x1e3/0x530 kernel/locking/lockdep.c:5754
<br>lock_sock_fast include/net/sock.h:1723 [inline]
<br>subflow_get_info+0x166/0xd20 net/mptcp/diag.c:28
<br>tcp_diag_put_ulp net/ipv4/tcp_diag.c:100 [inline]
<br>tcp_diag_get_aux+0x738/0x830 net/ipv4/tcp_diag.c:137
<br>inet_sk_diag_fill+0x10ed/0x1e00 net/ipv4/inet_diag.c:345
<br>inet_diag_dump_icsk+0x55b/0x1f80 net/ipv4/inet_diag.c:1061
<br>__inet_diag_dump+0x211/0x3a0 net/ipv4/inet_diag.c:1263
<br>inet_diag_dump_compat+0x1c1/0x2d0 net/ipv4/inet_diag.c:1371
<br>netlink_dump+0x59b/0xc80 net/netlink/af_netlink.c:2264
<br>__netlink_dump_start+0x5df/0x790 net/netlink/af_netlink.c:2370
<br>netlink_dump_start include/linux/netlink.h:338 [inline]
<br>inet_diag_rcv_msg_compat+0x209/0x4c0 net/ipv4/inet_diag.c:1405
<br>sock_diag_rcv_msg+0xe7/0x410
<br>netlink_rcv_skb+0x1e3/0x430 net/netlink/af_netlink.c:2543
<br>sock_diag_rcv+0x2a/0x40 net/core/sock_diag.c:280
<br>netlink_unicast_kernel net/netlink/af_netlink.c:1341 [inline]
<br>netlink_unicast+0x7ea/0x980 net/netlink/af_netlink.c:1367
<br>netlink_sendmsg+0xa3b/0xd70 net/netlink/af_netlink.c:1908
<br>sock_sendmsg_nosec net/socket.c:730 [inline]
<br>__sock_sendmsg+0x221/0x270 net/socket.c:745
<br>____sys_sendmsg+0x525/0x7d0 net/socket.c:2584
<br>___sys_sendmsg net/socket.c:2638 [inline]
<br>__sys_sendmsg+0x2b0/0x3a0 net/socket.c:2667
<br>do_syscall_64+0xf9/0x240
<br>entry_SYSCALL_64_after_hwframe+0x6f/0x77
<br>
<br>As noted by Eric we can break the lock dependency chain avoid
<br>dumping
<br>---truncated---</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26781</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26780</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>af_unix: Fix task hung while purging oob_skb in GC.
<br>
<br>syzbot reported a task hung; at the same time, GC was looping infinitely
<br>in list_for_each_entry_safe() for OOB skb. [0]
<br>
<br>syzbot demonstrated that the list_for_each_entry_safe() was not actually
<br>safe in this case.
<br>
<br>A single skb could have references for multiple sockets. If we free such
<br>a skb in the list_for_each_entry_safe(), the current and next sockets
could
<br>be unlinked in a single iteration.
<br>
<br>unix_notinflight() uses list_del_init() to unlink the socket, so the
<br>prefetched next socket forms a loop itself and list_for_each_entry_safe()
<br>never stops.
<br>
<br>Here, we must use while() and make sure we always fetch the first socket.
<br>
<br>[0]:
<br>Sending NMI from CPU 0 to CPUs 1:
<br>NMI backtrace for cpu 1
<br>CPU: 1 PID: 5065 Comm: syz-executor236 Not tainted 6.8.0-rc3-syzkaller-00136-g1f719a2f3fa6
#0
<br>Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS
Google 01/25/2024
<br>RIP: 0010:preempt_count arch/x86/include/asm/preempt.h:26 [inline]
<br>RIP: 0010:check_kcov_mode kernel/kcov.c:173 [inline]
<br>RIP: 0010:__sanitizer_cov_trace_pc+0xd/0x60 kernel/kcov.c:207
<br>Code: cc cc cc cc 66 0f 1f 84 00 00 00 00 00 90 90 90 90 90 90 90 90 90
90 90 90 90 90 90 90 f3 0f 1e fa 65 48 8b 14 25 40 c2 03 00 &lt;65&gt;
8b 05 b4 7c 78 7e a9 00 01 ff 00 48 8b 34 24 74 0f f6 c4 01 74
<br>RSP: 0018:ffffc900033efa58 EFLAGS: 00000283
<br>RAX: ffff88807b077800 RBX: ffff88807b077800 RCX: 1ffffffff27b1189
<br>RDX: ffff88802a5a3b80 RSI: ffffffff8968488d RDI: ffff88807b077f70
<br>RBP: ffffc900033efbb0 R08: 0000000000000001 R09: fffffbfff27a900c
<br>R10: ffffffff93d48067 R11: ffffffff8ae000eb R12: ffff88807b077800
<br>R13: dffffc0000000000 R14: ffff88807b077e40 R15: 0000000000000001
<br>FS: 0000000000000000(0000) GS:ffff8880b9500000(0000) knlGS:0000000000000000
<br>CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033
<br>CR2: 0000564f4fc1e3a8 CR3: 000000000d57a000 CR4: 00000000003506f0
<br>DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
<br>DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
<br>Call Trace:
<br>&lt;NMI&gt;
<br>&lt;/NMI&gt;
<br>&lt;TASK&gt;
<br>unix_gc+0x563/0x13b0 net/unix/garbage.c:319
<br>unix_release_sock+0xa93/0xf80 net/unix/af_unix.c:683
<br>unix_release+0x91/0xf0 net/unix/af_unix.c:1064
<br>__sock_release+0xb0/0x270 net/socket.c:659
<br>sock_close+0x1c/0x30 net/socket.c:1421
<br>__fput+0x270/0xb80 fs/file_table.c:376
<br>task_work_run+0x14f/0x250 kernel/task_work.c:180
<br>exit_task_work include/linux/task_work.h:38 [inline]
<br>do_exit+0xa8a/0x2ad0 kernel/exit.c:871
<br>do_group_exit+0xd4/0x2a0 kernel/exit.c:1020
<br>__do_sys_exit_group kernel/exit.c:1031 [inline]
<br>__se_sys_exit_group kernel/exit.c:1029 [inline]
<br>__x64_sys_exit_group+0x3e/0x50 kernel/exit.c:1029
<br>do_syscall_x64 arch/x86/entry/common.c:52 [inline]
<br>do_syscall_64+0xd5/0x270 arch/x86/entry/common.c:83
<br>entry_SYSCALL_64_after_hwframe+0x6f/0x77
<br>RIP: 0033:0x7f9d6cbdac09
<br>Code: Unable to access opcode bytes at 0x7f9d6cbdabdf.
<br>RSP: 002b:00007fff5952feb8 EFLAGS: 00000246 ORIG_RAX: 00000000000000e7
<br>RAX: ffffffffffffffda RBX: 0000000000000000 RCX: 00007f9d6cbdac09
<br>RDX: 000000000000003c RSI: 00000000000000e7 RDI: 0000000000000000
<br>RBP: 00007f9d6cc552b0 R08: ffffffffffffffb8 R09: 0000000000000006
<br>R10: 0000000000000006 R11: 0000000000000246 R12: 00007f9d6cc552b0
<br>R13: 0000000000000000 R14: 00007f9d6cc55d00 R15: 00007f9d6cbabe70
<br>&lt;/TASK&gt;</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26780</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26750</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>af_unix: Drop oob_skb ref before purging queue in GC.
<br>
<br>syzbot reported another task hung in __unix_gc(). [0]
<br>
<br>The current while loop assumes that all of the left candidates
<br>have oob_skb and calling kfree_skb(oob_skb) releases the remaining
<br>candidates.
<br>
<br>However, I missed a case that oob_skb has self-referencing fd and
<br>another fd and the latter sk is placed before the former in the
<br>candidate list. Then, the while loop never proceeds, resulting
<br>the task hung.
<br>
<br>__unix_gc() has the same loop just before purging the collected skb,
<br>so we can call kfree_skb(oob_skb) there and let __skb_queue_purge()
<br>release all inflight sockets.
<br>
<br>[0]:
<br>Sending NMI from CPU 0 to CPUs 1:
<br>NMI backtrace for cpu 1
<br>CPU: 1 PID: 2784 Comm: kworker/u4:8 Not tainted 6.8.0-rc4-syzkaller-01028-g71b605d32017
#0
<br>Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS
Google 01/25/2024
<br>Workqueue: events_unbound __unix_gc
<br>RIP: 0010:__sanitizer_cov_trace_pc+0x0/0x70 kernel/kcov.c:200
<br>Code: 89 fb e8 23 00 00 00 48 8b 3d 84 f5 1a 0c 48 89 de 5b e9 43 26 57
00 0f 1f 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 &lt;f3&gt;
0f 1e fa 48 8b 04 24 65 48 8b 0d 90 52 70 7e 65 8b 15 91 52 70
<br>RSP: 0018:ffffc9000a17fa78 EFLAGS: 00000287
<br>RAX: ffffffff8a0a6108 RBX: ffff88802b6c2640 RCX: ffff88802c0b3b80
<br>RDX: 0000000000000000 RSI: 0000000000000002 RDI: 0000000000000000
<br>RBP: ffffc9000a17fbf0 R08: ffffffff89383f1d R09: 1ffff1100ee5ff84
<br>R10: dffffc0000000000 R11: ffffed100ee5ff85 R12: 1ffff110056d84ee
<br>R13: ffffc9000a17fae0 R14: 0000000000000000 R15: ffffffff8f47b840
<br>FS: 0000000000000000(0000) GS:ffff8880b9500000(0000) knlGS:0000000000000000
<br>CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033
<br>CR2: 00007ffef5687ff8 CR3: 0000000029b34000 CR4: 00000000003506f0
<br>DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
<br>DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
<br>Call Trace:
<br>&lt;NMI&gt;
<br>&lt;/NMI&gt;
<br>&lt;TASK&gt;
<br>__unix_gc+0xe69/0xf40 net/unix/garbage.c:343
<br>process_one_work kernel/workqueue.c:2633 [inline]
<br>process_scheduled_works+0x913/0x1420 kernel/workqueue.c:2706
<br>worker_thread+0xa5f/0x1000 kernel/workqueue.c:2787
<br>kthread+0x2ef/0x390 kernel/kthread.c:388
<br>ret_from_fork+0x4b/0x80 arch/x86/kernel/process.c:147
<br>ret_from_fork_asm+0x1b/0x30 arch/x86/entry/entry_64.S:242
<br>&lt;/TASK&gt;</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26750</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26746</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>dmaengine: idxd: Ensure safe user copy of completion record
<br>
<br>If CONFIG_HARDENED_USERCOPY is enabled, copying completion record from
<br>event log cache to user triggers a kernel bug.
<br>
<br>[ 1987.159822] usercopy: Kernel memory exposure attempt detected from
SLUB object 'dsa0' (offset 74, size 31)!
<br>[ 1987.170845] ------------[ cut here ]------------
<br>[ 1987.176086] kernel BUG at mm/usercopy.c:102!
<br>[ 1987.180946] invalid opcode: 0000 [#1] PREEMPT SMP NOPTI
<br>[ 1987.186866] CPU: 17 PID: 528 Comm: kworker/17:1 Not tainted 6.8.0-rc2+
#5
<br>[ 1987.194537] Hardware name: Intel Corporation AvenueCity/AvenueCity,
BIOS BHSDCRB1.86B.2492.D03.2307181620 07/18/2023
<br>[ 1987.206405] Workqueue: wq0.0 idxd_evl_fault_work [idxd]
<br>[ 1987.212338] RIP: 0010:usercopy_abort+0x72/0x90
<br>[ 1987.217381] Code: 58 65 9c 50 48 c7 c2 17 85 61 9c 57 48 c7 c7 98 fd
6b 9c 48 0f 44 d6 48 c7 c6 b3 08 62 9c 4c 89 d1 49 0f 44 f3 e8 1e 2e d5
ff &lt;0f&gt; 0b 49 c7 c1 9e 42 61 9c 4c 89 cf 4d 89 c8 eb a9 66 66 2e
0f 1f
<br>[ 1987.238505] RSP: 0018:ff62f5cf20607d60 EFLAGS: 00010246
<br>[ 1987.244423] RAX: 000000000000005f RBX: 000000000000001f RCX: 0000000000000000
<br>[ 1987.252480] RDX: 0000000000000000 RSI: ffffffff9c61429e RDI: 00000000ffffffff
<br>[ 1987.260538] RBP: ff62f5cf20607d78 R08: ff2a6a89ef3fffe8 R09: 00000000fffeffff
<br>[ 1987.268595] R10: ff2a6a89eed00000 R11: 0000000000000003 R12: ff2a66934849c89a
<br>[ 1987.276652] R13: 0000000000000001 R14: ff2a66934849c8b9 R15: ff2a66934849c899
<br>[ 1987.284710] FS: 0000000000000000(0000) GS:ff2a66b22fe40000(0000) knlGS:0000000000000000
<br>[ 1987.293850] CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033
<br>[ 1987.300355] CR2: 00007fe291a37000 CR3: 000000010fbd4005 CR4: 0000000000f71ef0
<br>[ 1987.308413] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
<br>[ 1987.316470] DR3: 0000000000000000 DR6: 00000000fffe07f0 DR7: 0000000000000400
<br>[ 1987.324527] PKRU: 55555554
<br>[ 1987.327622] Call Trace:
<br>[ 1987.330424] &lt;TASK&gt;
<br>[ 1987.332826] ? show_regs+0x6e/0x80
<br>[ 1987.336703] ? die+0x3c/0xa0
<br>[ 1987.339988] ? do_trap+0xd4/0xf0
<br>[ 1987.343662] ? do_error_trap+0x75/0xa0
<br>[ 1987.347922] ? usercopy_abort+0x72/0x90
<br>[ 1987.352277] ? exc_invalid_op+0x57/0x80
<br>[ 1987.356634] ? usercopy_abort+0x72/0x90
<br>[ 1987.360988] ? asm_exc_invalid_op+0x1f/0x30
<br>[ 1987.365734] ? usercopy_abort+0x72/0x90
<br>[ 1987.370088] __check_heap_object+0xb7/0xd0
<br>[ 1987.374739] __check_object_size+0x175/0x2d0
<br>[ 1987.379588] idxd_copy_cr+0xa9/0x130 [idxd]
<br>[ 1987.384341] idxd_evl_fault_work+0x127/0x390 [idxd]
<br>[ 1987.389878] process_one_work+0x13e/0x300
<br>[ 1987.394435] ? __pfx_worker_thread+0x10/0x10
<br>[ 1987.399284] worker_thread+0x2f7/0x420
<br>[ 1987.403544] ? <em>raw</em>spin_unlock_irqrestore+0x2b/0x50
<br>[ 1987.409171] ? __pfx_worker_thread+0x10/0x10
<br>[ 1987.414019] kthread+0x107/0x140
<br>[ 1987.417693] ? __pfx_kthread+0x10/0x10
<br>[ 1987.421954] ret_from_fork+0x3d/0x60
<br>[ 1987.426019] ? __pfx_kthread+0x10/0x10
<br>[ 1987.430281] ret_from_fork_asm+0x1b/0x30
<br>[ 1987.434744] &lt;/TASK&gt;
<br>
<br>The issue arises because event log cache is created using
<br>kmem_cache_create() which is not suitable for user copy.
<br>
<br>Fix the issue by creating event log cache with
<br>kmem_cache_create_usercopy(), ensuring safe user copy.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26746</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26745</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>powerpc/pseries/iommu: IOMMU table is not initialized for kdump over SR-IOV
<br>
<br>When kdump kernel tries to copy dump data over SR-IOV, LPAR panics due
<br>to NULL pointer exception:
<br>
<br>Kernel attempted to read user page (0) - exploit attempt? (uid: 0)
<br>BUG: Kernel NULL pointer dereference on read at 0x00000000
<br>Faulting instruction address: 0xc000000020847ad4
<br>Oops: Kernel access of bad area, sig: 11 [#1]
<br>LE PAGE_SIZE=64K MMU=Radix SMP NR_CPUS=2048 NUMA pSeries
<br>Modules linked in: mlx5_core(+) vmx_crypto pseries_wdt papr_scm libnvdimm
mlxfw tls psample sunrpc fuse overlay squashfs loop
<br>CPU: 12 PID: 315 Comm: systemd-udevd Not tainted 6.4.0-Test102+ #12
<br>Hardware name: IBM,9080-HEX POWER10 (raw) 0x800200 0xf000006 of:IBM,FW1060.00
(NH1060_008) hv:phyp pSeries
<br>NIP: c000000020847ad4 LR: c00000002083b2dc CTR: 00000000006cd18c
<br>REGS: c000000029162ca0 TRAP: 0300 Not tainted (6.4.0-Test102+)
<br>MSR: 800000000280b033 &lt;SF,VEC,VSX,EE,FP,ME,IR,DR,RI,LE&gt; CR: 48288244
XER: 00000008
<br>CFAR: c00000002083b2d8 DAR: 0000000000000000 DSISR: 40000000 IRQMASK:
1
<br>...
<br>NIP <em>find</em>next_zero_bit+0x24/0x110
<br>LR bitmap_find_next_zero_area_off+0x5c/0xe0
<br>Call Trace:
<br>dev_printk_emit+0x38/0x48 (unreliable)
<br>iommu_area_alloc+0xc4/0x180
<br>iommu_range_alloc+0x1e8/0x580
<br>iommu_alloc+0x60/0x130
<br>iommu_alloc_coherent+0x158/0x2b0
<br>dma_iommu_alloc_coherent+0x3c/0x50
<br>dma_alloc_attrs+0x170/0x1f0
<br>mlx5_cmd_init+0xc0/0x760 [mlx5_core]
<br>mlx5_function_setup+0xf0/0x510 [mlx5_core]
<br>mlx5_init_one+0x84/0x210 [mlx5_core]
<br>probe_one+0x118/0x2c0 [mlx5_core]
<br>local_pci_probe+0x68/0x110
<br>pci_call_probe+0x68/0x200
<br>pci_device_probe+0xbc/0x1a0
<br>really_probe+0x104/0x540
<br>__driver_probe_device+0xb4/0x230
<br>driver_probe_device+0x54/0x130
<br>__driver_attach+0x158/0x2b0
<br>bus_for_each_dev+0xa8/0x130
<br>driver_attach+0x34/0x50
<br>bus_add_driver+0x16c/0x300
<br>driver_register+0xa4/0x1b0
<br>__pci_register_driver+0x68/0x80
<br>mlx5_init+0xb8/0x100 [mlx5_core]
<br>do_one_initcall+0x60/0x300
<br>do_init_module+0x7c/0x2b0
<br>
<br>At the time of LPAR dump, before kexec hands over control to kdump
<br>kernel, DDWs (Dynamic DMA Windows) are scanned and added to the FDT.
<br>For the SR-IOV case, default DMA window "ibm,dma-window" is removed from
<br>the FDT and DDW added, for the device.
<br>
<br>Now, kexec hands over control to the kdump kernel.
<br>
<br>When the kdump kernel initializes, PCI busses are scanned and IOMMU
<br>group/tables created, in pci_dma_bus_setup_pSeriesLP(). For the SR-IOV
<br>case, there is no "ibm,dma-window". The original commit: b1fc44eaa9ba,
<br>fixes the path where memory is pre-mapped (direct mapped) to the DDW.
<br>When TCEs are direct mapped, there is no need to initialize IOMMU
<br>tables.
<br>
<br>iommu_table_setparms_lpar() only considers "ibm,dma-window" property
<br>when initiallizing IOMMU table. In the scenario where TCEs are
<br>dynamically allocated for SR-IOV, newly created IOMMU table is not
<br>initialized. Later, when the device driver tries to enter TCEs for the
<br>SR-IOV device, NULL pointer execption is thrown from iommu_area_alloc().
<br>
<br>The fix is to initialize the IOMMU table with DDW property stored in the
<br>FDT. There are 2 points to remember:
<br>
<br>\t1. For the dedicated adapter, kdump kernel would encounter both
<br>\t default and DDW in FDT. In this case, DDW property is used to
<br>\t initialize the IOMMU table.
<br>
<br>\t2. A DDW could be direct or dynamic mapped. kdump kernel would
<br>\t initialize IOMMU table and mark the existing DDW as
<br>\t "dynamic". This works fine since, at the time of table
<br>\t initialization, iommu_table_clear() makes some space in the
<br>\t DDW, for some predefined number of TCEs which are needed for
<br>\t kdump to succeed.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26745</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30565</p>
</td>
<td rowspan="1" colspan="1">
<p>An issue was discovered in SeaCMS version 12.9, allows remote attackers
to execute arbitrary code via admin notify.php.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30565</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29008</p>
</td>
<td rowspan="1" colspan="1">
<p>A problem has been identified in the CloudStack additional VM configuration
(extraconfig) feature which can be misused by anyone who has privilege
to deploy a VM instance or configure settings of an already deployed VM
instance, to configure additional VM configuration even when the feature
is not explicitly enabled by the administrator. In a KVM based CloudStack
environment, an attacker can exploit this issue to&nbsp;attach host devices
such as storage disks, and PCI and USB devices such as network adapters
and GPUs, in a regular VM instance that can be further exploited to gain
access to the underlying network and storage infrastructure resources,
and access any VM instance disks on the local storage.
<br>
<br>Users are advised to upgrade to version 4.18.1.1 or 4.19.0.1, which fixes
this issue.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29008</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29007</p>
</td>
<td rowspan="1" colspan="1">
<p>The CloudStack management server and secondary storage VM could be tricked
into making requests to restricted or random resources by means of following
301 HTTP redirects presented by external servers when downloading templates
or ISOs. Users are recommended to upgrade to version 4.18.1.1 or 4.19.0.1,
which fixes this issue.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29007</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29006</p>
</td>
<td rowspan="1" colspan="1">
<p>By default the CloudStack management server honours the x-forwarded-for
HTTP header and logs it as the source IP of an API request. This could
lead to authentication bypass and other operational problems should an
attacker decide to spoof their IP address this way. Users are recommended
to upgrade to CloudStack version 4.18.1.1 or 4.19.0.1, which fixes this
issue.
<br>
</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29006</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-25503</p>
</td>
<td rowspan="1" colspan="1">
<p>Cross Site Scripting (XSS) vulnerability in Advanced REST Client v.17.0.9
allows a remote attacker to execute arbitrary code and obtain sensitive
information via a crafted script to the edit details parameter of the New
Project function.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-25503</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2020-25730</p>
</td>
<td rowspan="1" colspan="1">
<p>Cross Site Scripting (XSS) vulnerability in ZoneMinder before version
1.34.21, allows remote attackers execute arbitrary code, escalate privileges,
and obtain sensitive information via PHP_SELF component in classic/views/download.php.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2020-25730</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29375</p>
</td>
<td rowspan="1" colspan="1">
<p>CSV Injection vulnerability in Addactis IBNRS v.3.10.3.107 allows a remote
attacker to execute arbitrary code via a crafted .ibnrs file to the Project
Description, Identifiers, Custom Triangle Name (inside Input Triangles)
and Yield Curve Name parameters.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29375</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-25200</p>
</td>
<td rowspan="1" colspan="1">
<p>An HTML injection vulnerability exists in the MT Safeline X-Ray X3310
webserver version NXG 19.05 that enables a remote attacker to render malicious
HTML and obtain sensitive information in a victim's browser.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-25200</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-25199</p>
</td>
<td rowspan="1" colspan="1">
<p>A reflected cross-site scripting (XSS) vulnerability exists in the MT
Safeline X-Ray X3310 webserver version NXG 19.05 that enables a remote
attacker to execute JavaScript code and obtain sensitive information in
a victim's browser.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-25199</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28520</p>
</td>
<td rowspan="1" colspan="1">
<p>File Upload vulnerability in Byzoro Networks Smart multi-service security
gateway intelligent management platform version S210, allows an attacker
to obtain sensitive information via the uploadfile.php component.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28520</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31025</p>
</td>
<td rowspan="1" colspan="1">
<p>SQL Injection vulnerability in ECshop 4.x allows an attacker to obtain
sensitive information via the file/article.php component.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31025</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29225</p>
</td>
<td rowspan="1" colspan="1">
<p>WRC-X3200GST3-B v1.25 and earlier, and WRC-G01-W v1.24 and earlier allow
a network-adjacent unauthenticated attacker to obtain the configuration
file containing sensitive information by sending a specially crafted request.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29225</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29167</p>
</td>
<td rowspan="1" colspan="1">
<p>SVR-116 firmware version 1.6.0.30028871 allows a remote authenticated
attacker with an administrative privilege to execute arbitrary OS commands
by sending a specially crafted request to the product.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29167</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26258</p>
</td>
<td rowspan="1" colspan="1">
<p>OS command injection vulnerability in WRC-X3200GST3-B v1.25 and earlier,
and WRC-G01-W v1.24 and earlier allows a network-adjacent attacker with
credentials to execute arbitrary OS commands by sending a specially crafted
request to the product.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26258</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-25568</p>
</td>
<td rowspan="1" colspan="1">
<p>OS command injection vulnerability in WRC-X3200GST3-B v1.25 and earlier,
and WRC-G01-W v1.24 and earlier allows a network-adjacent unauthenticated
attacker to execute arbitrary OS commands by sending a specially crafted
request to the product.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-25568</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29413</p>
</td>
<td rowspan="1" colspan="1">
<p>Cross Site Scripting vulnerability in Webasyst v.2.9.9 allows a remote
attacker to run arbitrary code via the Instant messenger field in the Contact
info function.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29413</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27705</p>
</td>
<td rowspan="1" colspan="1">
<p>Cross Site Scripting vulnerability in Leantime v3.0.6 allows attackers
to execute arbitrary code via upload of crafted PDF file to the files/browse
endpoint.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27705</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52043</p>
</td>
<td rowspan="1" colspan="1">
<p>An issue in D-Link COVR 1100, 1102, 1103 AC1200 Dual-Band Whole-Home Mesh
Wi-Fi System (Hardware Rev B1) truncates Wireless Access Point Passwords
(WPA-PSK) allowing an attacker to gain unauthorized network access via
weak authentication controls.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52043</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27706</p>
</td>
<td rowspan="1" colspan="1">
<p>Cross Site Scripting vulnerability in Huly Platform v.0.6.202 allows attackers
to execute arbitrary code via upload of crafted SVG file to issues.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27706</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2758</p>
</td>
<td rowspan="1" colspan="1">
<p>Tempesta FW rate limits are not enabled by default. They are either set
too large to capture empty CONTINUATION frames attacks or too small to
handle normal HTTP requests appropriately.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2758</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2653</p>
</td>
<td rowspan="1" colspan="1">
<p>amphp/http will collect CONTINUATION frames in an unbounded buffer and
will not check a limit until it has received the set END_HEADERS flag,
resulting in an OOM crash.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2653</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30366</p>
</td>
<td rowspan="1" colspan="1">
<p>Foxit PDF Reader AcroForm Use-After-Free Remote Code Execution Vulnerability.
This vulnerability allows remote attackers to execute arbitrary code on
affected installations of Foxit PDF Reader. User interaction is required
to exploit this vulnerability in that the target must visit a malicious
page or open a malicious file.
<br>
<br>The specific flaw exists within the handling of AcroForms. The issue results
from the lack of validating the existence of an object prior to performing
operations on the object. An attacker can leverage this vulnerability to
execute code in the context of the current process. Was ZDI-CAN-23002.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30366</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30334</p>
</td>
<td rowspan="1" colspan="1">
<p>Foxit PDF Reader Doc Object Use-After-Free Remote Code Execution Vulnerability.
This vulnerability allows remote attackers to execute arbitrary code on
affected installations of Foxit PDF Reader. User interaction is required
to exploit this vulnerability in that the target must visit a malicious
page or open a malicious file.
<br>
<br>The specific flaw exists within the handling of Doc objects. The issue
results from the lack of validating the existence of an object prior to
performing operations on the object. An attacker can leverage this vulnerability
to execute code in the context of the current process. Was ZDI-CAN-22640.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30334</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30333</p>
</td>
<td rowspan="1" colspan="1">
<p>Foxit PDF Reader Doc Object Use-After-Free Remote Code Execution Vulnerability.
This vulnerability allows remote attackers to execute arbitrary code on
affected installations of Foxit PDF Reader. User interaction is required
to exploit this vulnerability in that the target must visit a malicious
page or open a malicious file.
<br>
<br>The specific flaw exists within the handling of Doc objects. The issue
results from the lack of validating the existence of an object prior to
performing operations on the object. An attacker can leverage this vulnerability
to execute code in the context of the current process. Was ZDI-CAN-22639.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30333</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30332</p>
</td>
<td rowspan="1" colspan="1">
<p>Foxit PDF Reader Doc Object Use-After-Free Remote Code Execution Vulnerability.
This vulnerability allows remote attackers to execute arbitrary code on
affected installations of Foxit PDF Reader. User interaction is required
to exploit this vulnerability in that the target must visit a malicious
page or open a malicious file.
<br>
<br>The specific flaw exists within the handling of Doc objects. The issue
results from the lack of validating the existence of an object prior to
performing operations on the object. An attacker can leverage this vulnerability
to execute code in the context of the current process. Was ZDI-CAN-22638.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30332</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30331</p>
</td>
<td rowspan="1" colspan="1">
<p>Foxit PDF Reader AcroForm Use-After-Free Remote Code Execution Vulnerability.
This vulnerability allows remote attackers to execute arbitrary code on
affected installations of Foxit PDF Reader. User interaction is required
to exploit this vulnerability in that the target must visit a malicious
page or open a malicious file.
<br>
<br>The specific flaw exists within the handling of Doc objects in AcroForms.
The issue results from the lack of validating the existence of an object
prior to performing operations on the object. An attacker can leverage
this vulnerability to execute code in the context of the current process.
Was ZDI-CAN-22637.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30331</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30330</p>
</td>
<td rowspan="1" colspan="1">
<p>Foxit PDF Reader AcroForm Use-After-Free Remote Code Execution Vulnerability.
This vulnerability allows remote attackers to execute arbitrary code on
affected installations of Foxit PDF Reader. User interaction is required
to exploit this vulnerability in that the target must visit a malicious
page or open a malicious file.
<br>
<br>The specific flaw exists within the handling of Doc objects in AcroForms.
The issue results from the lack of validating the existence of an object
prior to performing operations on the object. An attacker can leverage
this vulnerability to execute code in the context of the current process.
Was ZDI-CAN-22636.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30330</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30329</p>
</td>
<td rowspan="1" colspan="1">
<p>Foxit PDF Reader Annotation Use-After-Free Information Disclosure Vulnerability.
This vulnerability allows remote attackers to disclose sensitive information
on affected installations of Foxit PDF Reader. User interaction is required
to exploit this vulnerability in that the target must visit a malicious
page or open a malicious file.
<br>
<br>The specific flaw exists within the handling of Annotation objects. The
issue results from the lack of validating the existence of an object prior
to performing operations on the object. An attacker can leverage this in
conjunction with other vulnerabilities to execute arbitrary code in the
context of the current process. Was ZDI-CAN-22634.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30329</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30328</p>
</td>
<td rowspan="1" colspan="1">
<p>Foxit PDF Reader AcroForm Use-After-Free Remote Code Execution Vulnerability.
This vulnerability allows remote attackers to execute arbitrary code on
affected installations of Foxit PDF Reader. User interaction is required
to exploit this vulnerability in that the target must visit a malicious
page or open a malicious file.
<br>
<br>The specific flaw exists within the handling of Doc objects in AcroForms.
The issue results from the lack of validating the existence of an object
prior to performing operations on the object. An attacker can leverage
this vulnerability to execute code in the context of the current process.
Was ZDI-CAN-22633.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30328</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30327</p>
</td>
<td rowspan="1" colspan="1">
<p>Foxit PDF Reader template Use-After-Free Remote Code Execution Vulnerability.
This vulnerability allows remote attackers to execute arbitrary code on
affected installations of Foxit PDF Reader. User interaction is required
to exploit this vulnerability in that the target must visit a malicious
page or open a malicious file.
<br>
<br>The specific flaw exists within the handling of template objects. The
issue results from the lack of validating the existence of an object prior
to performing operations on the object. An attacker can leverage this vulnerability
to execute code in the context of the current process. Was ZDI-CAN-22632.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30327</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30326</p>
</td>
<td rowspan="1" colspan="1">
<p>Foxit PDF Reader Doc Object Use-After-Free Remote Code Execution Vulnerability.
This vulnerability allows remote attackers to execute arbitrary code on
affected installations of Foxit PDF Reader. User interaction is required
to exploit this vulnerability in that the target must visit a malicious
page or open a malicious file.
<br>
<br>The specific flaw exists within the handling of Doc objects. The issue
results from the lack of validating the existence of an object prior to
performing operations on the object. An attacker can leverage this vulnerability
to execute code in the context of the current process. Was ZDI-CAN-22593.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30326</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30325</p>
</td>
<td rowspan="1" colspan="1">
<p>Foxit PDF Reader AcroForm Use-After-Free Remote Code Execution Vulnerability.
This vulnerability allows remote attackers to execute arbitrary code on
affected installations of Foxit PDF Reader. User interaction is required
to exploit this vulnerability in that the target must visit a malicious
page or open a malicious file.
<br>
<br>The specific flaw exists within the handling of Doc objects in AcroForms.
The issue results from the lack of validating the existence of an object
prior to performing operations on the object. An attacker can leverage
this vulnerability to execute code in the context of the current process.
Was ZDI-CAN-22592.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30325</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30324</p>
</td>
<td rowspan="1" colspan="1">
<p>Foxit PDF Reader Doc Object Use-After-Free Remote Code Execution Vulnerability.
This vulnerability allows remote attackers to execute arbitrary code on
affected installations of Foxit PDF Reader. User interaction is required
to exploit this vulnerability in that the target must visit a malicious
page or open a malicious file.
<br>
<br>The specific flaw exists within the handling of Doc objects. The issue
results from the lack of validating the existence of an object prior to
performing operations on the object. An attacker can leverage this vulnerability
to execute code in the context of the current process. Was ZDI-CAN-22576.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30324</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30323</p>
</td>
<td rowspan="1" colspan="1">
<p>Foxit PDF Reader template Out-Of-Bounds Read Remote Code Execution Vulnerability.
This vulnerability allows remote attackers to execute arbitrary code on
affected installations of Foxit PDF Reader. User interaction is required
to exploit this vulnerability in that the target must visit a malicious
page or open a malicious file.
<br>
<br>The specific flaw exists within the handling of template objects. The
issue results from the lack of proper validation of user-supplied data,
which can result in a read past the end of an allocated object. An attacker
can leverage this vulnerability to execute code in the context of the current
process. Was ZDI-CAN-22501.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30323</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30322</p>
</td>
<td rowspan="1" colspan="1">
<p>Foxit PDF Reader AcroForm Use-After-Free Remote Code Execution Vulnerability.
This vulnerability allows remote attackers to execute arbitrary code on
affected installations of Foxit PDF Reader. User interaction is required
to exploit this vulnerability in that the target must visit a malicious
page or open a malicious file.
<br>
<br>The specific flaw exists within the handling of AcroForms. The issue results
from the lack of validating the existence of an object prior to performing
operations on the object. An attacker can leverage this vulnerability to
execute code in the context of the current process. Was ZDI-CAN-22499.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30322</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27674</p>
</td>
<td rowspan="1" colspan="1">
<p>Macro Expert through 4.9.4 allows BUILTIN\\Users:(OI)(CI)(M) access to
the "%PROGRAMFILES(X86)%\\GrassSoft\\Macro Expert" folder and thus an unprivileged
user can escalate to SYSTEM by replacing the MacroService.exe binary.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27674</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27346</p>
</td>
<td rowspan="1" colspan="1">
<p>Kofax Power PDF PDF File Parsing Out-Of-Bounds Read Information Disclosure
Vulnerability. This vulnerability allows remote attackers to disclose sensitive
information on affected installations of Kofax Power PDF. User interaction
is required to exploit this vulnerability in that the target must visit
a malicious page or open a malicious file.
<br>
<br>The specific flaw exists within the handling of PDF files. The issue results
from the lack of proper validation of user-supplied data, which can result
in a read past the end of an allocated buffer. An attacker can leverage
this in conjunction with other vulnerabilities to execute arbitrary code
in the context of the current process. Was ZDI-CAN-22934.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27346</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27345</p>
</td>
<td rowspan="1" colspan="1">
<p>Kofax Power PDF PDF File Parsing Out-Of-Bounds Read Information Disclosure
Vulnerability. This vulnerability allows remote attackers to disclose sensitive
information on affected installations of Kofax Power PDF. User interaction
is required to exploit this vulnerability in that the target must visit
a malicious page or open a malicious file.
<br>
<br>The specific flaw exists within the handling of PDF files. The issue results
from the lack of proper validation of user-supplied data, which can result
in a read past the end of an allocated object. An attacker can leverage
this in conjunction with other vulnerabilities to execute arbitrary code
in the context of the current process. Was ZDI-CAN-22932.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27345</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27344</p>
</td>
<td rowspan="1" colspan="1">
<p>Kofax Power PDF PDF File Parsing Memory Corruption Remote Code Execution
Vulnerability. This vulnerability allows remote attackers to execute arbitrary
code on affected installations of Kofax Power PDF. User interaction is
required to exploit this vulnerability in that the target must visit a
malicious page or open a malicious file.
<br>
<br>The specific flaw exists within the parsing of PDF files. The issue results
from the lack of proper validation of user-supplied data, which can result
in a memory corruption condition. An attacker can leverage this vulnerability
to execute code in the context of the current process. Was ZDI-CAN-22931.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27344</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27343</p>
</td>
<td rowspan="1" colspan="1">
<p>Kofax Power PDF PDF File Parsing Out-Of-Bounds Read Information Disclosure
Vulnerability. This vulnerability allows remote attackers to disclose sensitive
information on affected installations of Kofax Power PDF. User interaction
is required to exploit this vulnerability in that the target must visit
a malicious page or open a malicious file.
<br>
<br>The specific flaw exists within the parsing of PDF files. The issue results
from the lack of proper validation of user-supplied data, which can result
in a read past the end of an allocated object. An attacker can leverage
this in conjunction with other vulnerabilities to execute arbitrary code
in the context of the current process. Was ZDI-CAN-22929.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27343</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27342</p>
</td>
<td rowspan="1" colspan="1">
<p>Kofax Power PDF PDF File Parsing Out-Of-Bounds Write Remote Code Execution
Vulnerability. This vulnerability allows remote attackers to execute arbitrary
code on affected installations of Kofax Power PDF. User interaction is
required to exploit this vulnerability in that the target must visit a
malicious page or open a malicious file.
<br>
<br>The specific flaw exists within the parsing of PDF files. The issue results
from the lack of proper validation of user-supplied data, which can result
in a write past the end of an allocated buffer. An attacker can leverage
this vulnerability to execute code in the context of the current process.
Was ZDI-CAN-22928.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27342</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27341</p>
</td>
<td rowspan="1" colspan="1">
<p>Kofax Power PDF PDF File Parsing Heap-based Buffer Overflow Remote Code
Execution Vulnerability. This vulnerability allows remote attackers to
execute arbitrary code on affected installations of Kofax Power PDF. User
interaction is required to exploit this vulnerability in that the target
must visit a malicious page or open a malicious file.
<br>
<br>The specific flaw exists within the parsing of PDF files. The issue results
from the lack of proper validation of the length of user-supplied data
prior to copying it to a fixed-length heap-based buffer. An attacker can
leverage this vulnerability to execute code in the context of the current
process. Was ZDI-CAN-22927.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27341</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27340</p>
</td>
<td rowspan="1" colspan="1">
<p>Kofax Power PDF PDF File Parsing Heap-based Buffer Overflow Remote Code
Execution Vulnerability. This vulnerability allows remote attackers to
execute arbitrary code on affected installations of Kofax Power PDF. User
interaction is required to exploit this vulnerability in that the target
must visit a malicious page or open a malicious file.
<br>
<br>The specific flaw exists within the parsing of PDF files. The issue results
from the lack of proper validation of the length of user-supplied data
prior to copying it to a fixed-length heap-based buffer. An attacker can
leverage this vulnerability to execute code in the context of the current
process. Was ZDI-CAN-22926.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27340</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27339</p>
</td>
<td rowspan="1" colspan="1">
<p>Kofax Power PDF PDF File Parsing Out-Of-Bounds Write Remote Code Execution
Vulnerability. This vulnerability allows remote attackers to execute arbitrary
code on affected installations of Kofax Power PDF. User interaction is
required to exploit this vulnerability in that the target must visit a
malicious page or open a malicious file.
<br>
<br>The specific flaw exists within the parsing of PDF files. The issue results
from the lack of proper validation of user-supplied data, which can result
in a write past the end of an allocated buffer. An attacker can leverage
this vulnerability to execute code in the context of the current process.
Was ZDI-CAN-22925.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27339</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27338</p>
</td>
<td rowspan="1" colspan="1">
<p>Kofax Power PDF app response Out-Of-Bounds Read Remote Code Execution
Vulnerability. This vulnerability allows remote attackers to execute arbitrary
code on affected installations of Kofax Power PDF. User interaction is
required to exploit this vulnerability in that the target must visit a
malicious page or open a malicious file.
<br>
<br>The specific flaw exists within the implementation of the app.response
method. The issue results from the lack of proper validation of user-supplied
data, which can result in a read past the end of an allocated object. An
attacker can leverage this vulnerability to execute code in the context
of the current process. Was ZDI-CAN-22588.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27338</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27337</p>
</td>
<td rowspan="1" colspan="1">
<p>Kofax Power PDF TIF File Parsing Stack-based Buffer Overflow Remote Code
Execution Vulnerability. This vulnerability allows remote attackers to
execute arbitrary code on affected installations of Kofax Power PDF. User
interaction is required to exploit this vulnerability in that the target
must visit a malicious page or open a malicious file.
<br>
<br>The specific flaw exists within the parsing of TIF files. The issue results
from the lack of proper validation of the length of user-supplied data
prior to copying it to a fixed-length stack-based buffer. An attacker can
leverage this vulnerability to execute code in the context of the current
process. Was ZDI-CAN-22033.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27337</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27336</p>
</td>
<td rowspan="1" colspan="1">
<p>Kofax Power PDF PNG File Parsing Out-Of-Bounds Read Information Disclosure
Vulnerability. This vulnerability allows remote attackers to disclose sensitive
information on affected installations of Kofax Power PDF. User interaction
is required to exploit this vulnerability in that the target must visit
a malicious page or open a malicious file.
<br>
<br>The specific flaw exists within the parsing of PNG files. The issue results
from the lack of proper validation of user-supplied data, which can result
in a read past the end of an allocated object. An attacker can leverage
this in conjunction with other vulnerabilities to execute arbitrary code
in the context of the current process. Was ZDI-CAN-22022.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27336</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27335</p>
</td>
<td rowspan="1" colspan="1">
<p>Kofax Power PDF PNG File Parsing Out-Of-Bounds Read Remote Code Execution
Vulnerability. This vulnerability allows remote attackers to execute arbitrary
code on affected installations of Kofax Power PDF. User interaction is
required to exploit this vulnerability in that the target must visit a
malicious page or open a malicious file.
<br>
<br>The specific flaw exists within the handling of PNG files. The issue results
from the lack of proper validation of user-supplied data, which can result
in a read past the end of an allocated object. An attacker can leverage
this vulnerability to execute code in the context of the current process.
Was ZDI-CAN-22018.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27335</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26779</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>wifi: mac80211: fix race condition on enabling fast-xmit
<br>
<br>fast-xmit must only be enabled after the sta has been uploaded to the
driver,
<br>otherwise it could end up passing the not-yet-uploaded sta via drv_tx
calls
<br>to the driver, leading to potential crashes because of uninitialized drv_priv
<br>data.
<br>Add a missing sta-&gt;uploaded check and re-check fast xmit after inserting
a sta.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26779</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26778</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>fbdev: savage: Error out if pixclock equals zero
<br>
<br>The userspace program could pass any values to the driver through
<br>ioctl() interface. If the driver doesn't check the value of pixclock,
<br>it may cause divide-by-zero error.
<br>
<br>Although pixclock is checked in savagefb_decode_var(), but it is not
<br>checked properly in savagefb_probe(). Fix this by checking whether
<br>pixclock is zero in the function savagefb_check_var() before
<br>info-&gt;var.pixclock is used as the divisor.
<br>
<br>This is similar to CVE-2022-3061 in i740fb which was fixed by
<br>commit 15cf0b8.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26778</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26777</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>fbdev: sis: Error out if pixclock equals zero
<br>
<br>The userspace program could pass any values to the driver through
<br>ioctl() interface. If the driver doesn't check the value of pixclock,
<br>it may cause divide-by-zero error.
<br>
<br>In sisfb_check_var(), var-&gt;pixclock is used as a divisor to caculate
<br>drate before it is checked against zero. Fix this by checking it
<br>at the beginning.
<br>
<br>This is similar to CVE-2022-3061 in i740fb which was fixed by
<br>commit 15cf0b8.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26777</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26776</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>spi: hisi-sfc-v3xx: Return IRQ_NONE if no interrupts were detected
<br>
<br>Return IRQ_NONE from the interrupt handler when no interrupt was
<br>detected. Because an empty interrupt will cause a null pointer error:
<br>
<br>Unable to handle kernel NULL pointer dereference at virtual
<br>address 0000000000000008
<br>Call trace:
<br>complete+0x54/0x100
<br>hisi_sfc_v3xx_isr+0x2c/0x40 [spi_hisi_sfc_v3xx]
<br>__handle_irq_event_percpu+0x64/0x1e0
<br>handle_irq_event+0x7c/0x1cc</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26776</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26774</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>ext4: avoid dividing by 0 in mb_update_avg_fragment_size() when block
bitmap corrupt
<br>
<br>Determine if bb_fragments is 0 instead of determining bb_free to eliminate
<br>the risk of dividing by zero when the block bitmap is corrupted.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26774</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26773</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>ext4: avoid allocating blocks from corrupted group in ext4_mb_try_best_found()
<br>
<br>Determine if the group block bitmap is corrupted before using ac_b_ex
in
<br>ext4_mb_try_best_found() to avoid allocating blocks from a group with
a
<br>corrupted block bitmap in the following concurrency and making the
<br>situation worse.
<br>
<br>ext4_mb_regular_allocator
<br>ext4_lock_group(sb, group)
<br>ext4_mb_good_group
<br>// check if the group bbitmap is corrupted
<br>ext4_mb_complex_scan_group
<br>// Scan group gets ac_b_ex but doesn't use it
<br>ext4_unlock_group(sb, group)
<br>ext4_mark_group_bitmap_corrupted(group)
<br>// The block bitmap was corrupted during
<br>// the group unlock gap.
<br>ext4_mb_try_best_found
<br>ext4_lock_group(ac-&gt;ac_sb, group)
<br>ext4_mb_use_best_found
<br>mb_mark_used
<br>// Allocating blocks in block bitmap corrupted group</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26773</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26772</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>ext4: avoid allocating blocks from corrupted group in ext4_mb_find_by_goal()
<br>
<br>Places the logic for checking if the group's block bitmap is corrupt under
<br>the protection of the group lock to avoid allocating blocks from the group
<br>with a corrupted block bitmap.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26772</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26771</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>dmaengine: ti: edma: Add some null pointer checks to the edma_probe
<br>
<br>devm_kasprintf() returns a pointer to dynamically allocated memory
<br>which can be NULL upon failure. Ensure the allocation was successful
<br>by checking the pointer validity.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26771</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26770</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>HID: nvidia-shield: Add missing null pointer checks to LED initialization
<br>
<br>devm_kasprintf() returns a pointer to dynamically allocated memory
<br>which can be NULL upon failure. Ensure the allocation was successful
<br>by checking the pointer validity.
<br>
<br>[<a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">jkosina@suse.com</a>:
tweak changelog a bit]</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26770</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26769</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>nvmet-fc: avoid deadlock on delete association path
<br>
<br>When deleting an association the shutdown path is deadlocking because
we
<br>try to flush the nvmet_wq nested. Avoid this by deadlock by deferring
<br>the put work into its own work item.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26769</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26768</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>LoongArch: Change acpi_core_pic[NR_CPUS] to acpi_core_pic[MAX_CORE_PIC]
<br>
<br>With default config, the value of NR_CPUS is 64. When HW platform has
<br>more then 64 cpus, system will crash on these platforms. MAX_CORE_PIC
<br>is the maximum cpu number in MADT table (max physical number) which can
<br>exceed the supported maximum cpu number (NR_CPUS, max logical number),
<br>but kernel should not crash. Kernel should boot cpus with NR_CPUS, let
<br>the remainder cpus stay in BIOS.
<br>
<br>The potential crash reason is that the array acpi_core_pic[NR_CPUS] can
<br>be overflowed when parsing MADT table, and it is obvious that CORE_PIC
<br>should be corresponding to physical core rather than logical core, so
it
<br>is better to define the array as acpi_core_pic[MAX_CORE_PIC].
<br>
<br>With the patch, system can boot up 64 vcpus with qemu parameter -smp 128,
<br>otherwise system will crash with the following message.
<br>
<br>[ 0.000000] CPU 0 Unable to handle kernel paging request at virtual address
0000420000004259, era
<mark>90000000037a5f0c, ra</mark>90000000037a46ec
<br>[ 0.000000] Oops[#1]:
<br>[ 0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted 6.8.0-rc2+ #192
<br>[ 0.000000] Hardware name: QEMU QEMU Virtual Machine, BIOS unknown 2/2/2022
<br>[ 0.000000] pc 90000000037a5f0c ra 90000000037a46ec tp 9000000003c90000
sp 9000000003c93d60
<br>[ 0.000000] a0 0000000000000019 a1 9000000003d93bc0 a2 0000000000000000
a3 9000000003c93bd8
<br>[ 0.000000] a4 9000000003c93a74 a5 9000000083c93a67 a6 9000000003c938f0
a7 0000000000000005
<br>[ 0.000000] t0 0000420000004201 t1 0000000000000000 t2 0000000000000001
t3 0000000000000001
<br>[ 0.000000] t4 0000000000000003 t5 0000000000000000 t6 0000000000000030
t7 0000000000000063
<br>[ 0.000000] t8 0000000000000014 u0 ffffffffffffffff s9 0000000000000000
s0 9000000003caee98
<br>[ 0.000000] s1 90000000041b0480 s2 9000000003c93da0 s3 9000000003c93d98
s4 9000000003c93d90
<br>[ 0.000000] s5 9000000003caa000 s6 000000000a7fd000 s7 000000000f556b60
s8 000000000e0a4330
<br>[ 0.000000] ra: 90000000037a46ec platform_init+0x214/0x250
<br>[ 0.000000] ERA: 90000000037a5f0c efi_runtime_init+0x30/0x94
<br>[ 0.000000] CRMD: 000000b0 (PLV0 -IE -DA +PG DACF=CC DACM=CC -WE)
<br>[ 0.000000] PRMD: 00000000 (PPLV0 -PIE -PWE)
<br>[ 0.000000] EUEN: 00000000 (-FPE -SXE -ASXE -BTE)
<br>[ 0.000000] ECFG: 00070800 (LIE=11 VS=7)
<br>[ 0.000000] ESTAT: 00010000 [PIL] (IS= ECode=1 EsubCode=0)
<br>[ 0.000000] BADV: 0000420000004259
<br>[ 0.000000] PRID: 0014c010 (Loongson-64bit, Loongson-3A5000)
<br>[ 0.000000] Modules linked in:
<br>[ 0.000000] Process swapper (pid: 0, threadinfo=(____ptrval____), task=(____ptrval____))
<br>[ 0.000000] Stack : 9000000003c93a14 9000000003800898 90000000041844f8
90000000037a46ec
<br>[ 0.000000] 000000000a7fd000 0000000008290000 0000000000000000 0000000000000000
<br>[ 0.000000] 0000000000000000 0000000000000000 00000000019d8000 000000000f556b60
<br>[ 0.000000] 000000000a7fd000 000000000f556b08 9000000003ca7700 9000000003800000
<br>[ 0.000000] 9000000003c93e50 9000000003800898 9000000003800108 90000000037a484c
<br>[ 0.000000] 000000000e0a4330 000000000f556b60 000000000a7fd000 000000000f556b08
<br>[ 0.000000] 9000000003ca7700 9000000004184000 0000000000200000 000000000e02b018
<br>[ 0.000000] 000000000a7fd000 90000000037a0790 9000000003800108 0000000000000000
<br>[ 0.000000] 0000000000000000 000000000e0a4330 000000000f556b60 000000000a7fd000
<br>[ 0.000000] 000000000f556b08 000000000eaae298 000000000eaa5040 0000000000200000
<br>[ 0.000000] ...
<br>[ 0.000000] Call Trace:
<br>[ 0.000000] [&lt;90000000037a5f0c&gt;] efi_runtime_init+0x30/0x94
<br>[ 0.000000] [&lt;90000000037a46ec&gt;] platform_init+0x214/0x250
<br>[ 0.000000] [&lt;90000000037a484c&gt;] setup_arch+0x124/0x45c
<br>[ 0.000000] [&lt;90000000037a0790&gt;] start_kernel+0x90/0x670
<br>[ 0.000000] [&lt;900000000378b0d8&gt;] kernel_entry+0xd8/0xdc</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26768</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26767</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>drm/amd/display: fixed integer types and null check locations
<br>
<br>[why]:
<br>issues fixed:
<br>- comparison with wider integer type in loop condition which can cause
<br>infinite loops
<br>- pointer dereference before null check</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26767</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26766</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>IB/hfi1: Fix sdma.h tx-&gt;num_descs off-by-one error
<br>
<br>Unfortunately the commit <code>fd8958efe877</code> introduced another error
<br>causing the <code>descs</code> array to overflow. This reults in further
crashes
<br>easily reproducible by <code>sendmsg</code> system call.
<br>
<br>[ 1080.836473] general protection fault, probably for non-canonical address
0x400300015528b00a: 0000 [#1] PREEMPT SMP PTI
<br>[ 1080.869326] RIP: 0010:hfi1_ipoib_build_ib_tx_headers.constprop.0+0xe1/0x2b0
[hfi1]
<br>--
<br>[ 1080.974535] Call Trace:
<br>[ 1080.976990] &lt;TASK&gt;
<br>[ 1081.021929] hfi1_ipoib_send_dma_common+0x7a/0x2e0 [hfi1]
<br>[ 1081.027364] hfi1_ipoib_send_dma_list+0x62/0x270 [hfi1]
<br>[ 1081.032633] hfi1_ipoib_send+0x112/0x300 [hfi1]
<br>[ 1081.042001] ipoib_start_xmit+0x2a9/0x2d0 [ib_ipoib]
<br>[ 1081.046978] dev_hard_start_xmit+0xc4/0x210
<br>--
<br>[ 1081.148347] __sys_sendmsg+0x59/0xa0
<br>
<br>crash&gt; ipoib_txreq 0xffff9cfeba229f00
<br>struct ipoib_txreq {
<br>txreq = {
<br>list = {
<br>next = 0xffff9cfeba229f00,
<br>prev = 0xffff9cfeba229f00
<br>},
<br>descp = 0xffff9cfeba229f40,
<br>coalesce_buf = 0x0,
<br>wait = 0xffff9cfea4e69a48,
<br>complete = 0xffffffffc0fe0760 &lt;hfi1_ipoib_sdma_complete&gt;,
<br>packet_len = 0x46d,
<br>tlen = 0x0,
<br>num_desc = 0x0,
<br>desc_limit = 0x6,
<br>next_descq_idx = 0x45c,
<br>coalesce_idx = 0x0,
<br>flags = 0x0,
<br>descs = {{
<br>qw = {0x8024000120dffb00, 0x4} # SDMA_DESC0_FIRST_DESC_FLAG (bit 63)
<br>}, {
<br>qw = { 0x3800014231b108, 0x4}
<br>}, {
<br>qw = { 0x310000e4ee0fcf0, 0x8}
<br>}, {
<br>qw = { 0x3000012e9f8000, 0x8}
<br>}, {
<br>qw = { 0x59000dfb9d0000, 0x8}
<br>}, {
<br>qw = { 0x78000e02e40000, 0x8}
<br>}}
<br>},
<br>sdma_hdr = 0x400300015528b000, &lt;&lt;&lt; invalid pointer in the tx
request structure
<br>sdma_status = 0x0, SDMA_DESC0_LAST_DESC_FLAG (bit 62)
<br>complete = 0x0,
<br>priv = 0x0,
<br>txq = 0xffff9cfea4e69880,
<br>skb = 0xffff9d099809f400
<br>}
<br>
<br>If an SDMA send consists of exactly 6 descriptors and requires dword
<br>padding (in the 7th descriptor), the sdma_txreq descriptor array is not
<br>properly expanded and the packet will overflow into the container
<br>structure. This results in a panic when the send completion runs. The
<br>exact panic varies depending on what elements of the container structure
<br>get corrupted. The fix is to use the correct expression in
<br>_pad_sdma_tx_descs() to test the need to expand the descriptor array.
<br>
<br>With this patch the crashes are no longer reproducible and the machine
is
<br>stable.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26766</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26765</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>LoongArch: Disable IRQ before init_fn() for nonboot CPUs
<br>
<br>Disable IRQ before init_fn() for nonboot CPUs when hotplug, in order to
<br>silence such warnings (and also avoid potential errors due to unexpected
<br>interrupts):
<br>
<br>WARNING: CPU: 1 PID: 0 at kernel/rcu/tree.c:4503 rcu_cpu_starting+0x214/0x280
<br>CPU: 1 PID: 0 Comm: swapper/1 Not tainted 6.6.17+ #1198
<br>pc 90000000048e3334 ra 90000000047bd56c tp 900000010039c000 sp 900000010039fdd0
<br>a0 0000000000000001 a1 0000000000000006 a2 900000000802c040 a3 0000000000000000
<br>a4 0000000000000001 a5 0000000000000004 a6 0000000000000000 a7 90000000048e3f4c
<br>t0 0000000000000001 t1 9000000005c70968 t2 0000000004000000 t3 000000000005e56e
<br>t4 00000000000002e4 t5 0000000000001000 t6 ffffffff80000000 t7 0000000000040000
<br>t8 9000000007931638 u0 0000000000000006 s9 0000000000000004 s0 0000000000000001
<br>s1 9000000006356ac0 s2 9000000007244000 s3 0000000000000001 s4 0000000000000001
<br>s5 900000000636f000 s6 7fffffffffffffff s7 9000000002123940 s8 9000000001ca55f8
<br>ra: 90000000047bd56c tlb_init+0x24c/0x528
<br>ERA: 90000000048e3334 rcu_cpu_starting+0x214/0x280
<br>CRMD: 000000b0 (PLV0 -IE -DA +PG DACF=CC DACM=CC -WE)
<br>PRMD: 00000000 (PPLV0 -PIE -PWE)
<br>EUEN: 00000000 (-FPE -SXE -ASXE -BTE)
<br>ECFG: 00071000 (LIE=12 VS=7)
<br>ESTAT: 000c0000 [BRK] (IS= ECode=12 EsubCode=0)
<br>PRID: 0014c010 (Loongson-64bit, Loongson-3A5000)
<br>CPU: 1 PID: 0 Comm: swapper/1 Not tainted 6.6.17+ #1198
<br>Stack : 0000000000000000 9000000006375000 9000000005b61878 900000010039c000
<br>900000010039fa30 0000000000000000 900000010039fa38 900000000619a140
<br>9000000006456888 9000000006456880 900000010039f950 0000000000000001
<br>0000000000000001 cb0cb028ec7e52e1 0000000002b90000 9000000100348700
<br>0000000000000000 0000000000000001 ffffffff916d12f1 0000000000000003
<br>0000000000040000 9000000007930370 0000000002b90000 0000000000000004
<br>9000000006366000 900000000619a140 0000000000000000 0000000000000004
<br>0000000000000000 0000000000000009 ffffffffffc681f2 9000000002123940
<br>9000000001ca55f8 9000000006366000 90000000047a4828 00007ffff057ded8
<br>00000000000000b0 0000000000000000 0000000000000000 0000000000071000
<br>...
<br>Call Trace:
<br>[&lt;90000000047a4828&gt;] show_stack+0x48/0x1a0
<br>[&lt;9000000005b61874&gt;] dump_stack_lvl+0x84/0xcc
<br>[&lt;90000000047f60ac&gt;] __warn+0x8c/0x1e0
<br>[&lt;9000000005b0ab34&gt;] report_bug+0x1b4/0x280
<br>[&lt;9000000005b63110&gt;] do_bp+0x2d0/0x480
<br>[&lt;90000000047a2e20&gt;] handle_bp+0x120/0x1c0
<br>[&lt;90000000048e3334&gt;] rcu_cpu_starting+0x214/0x280
<br>[&lt;90000000047bd568&gt;] tlb_init+0x248/0x528
<br>[&lt;90000000047a4c44&gt;] per_cpu_trap_init+0x124/0x160
<br>[&lt;90000000047a19f4&gt;] cpu_probe+0x494/0xa00
<br>[&lt;90000000047b551c&gt;] start_secondary+0x3c/0xc0
<br>[&lt;9000000005b66134&gt;] smpboot_entry+0x50/0x58</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26765</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26764</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>fs/aio: Restrict kiocb_set_cancel_fn() to I/O submitted via libaio
<br>
<br>If kiocb_set_cancel_fn() is called for I/O submitted via io_uring, the
<br>following kernel warning appears:
<br>
<br>WARNING: CPU: 3 PID: 368 at fs/aio.c:598 kiocb_set_cancel_fn+0x9c/0xa8
<br>Call trace:
<br>kiocb_set_cancel_fn+0x9c/0xa8
<br>ffs_epfile_read_iter+0x144/0x1d0
<br>io_read+0x19c/0x498
<br>io_issue_sqe+0x118/0x27c
<br>io_submit_sqes+0x25c/0x5fc
<br>__arm64_sys_io_uring_enter+0x104/0xab0
<br>invoke_syscall+0x58/0x11c
<br>el0_svc_common+0xb4/0xf4
<br>do_el0_svc+0x2c/0xb0
<br>el0_svc+0x2c/0xa4
<br>el0t_64_sync_handler+0x68/0xb4
<br>el0t_64_sync+0x1a4/0x1a8
<br>
<br>Fix this by setting the IOCB_AIO_RW flag for read and write I/O that is
<br>submitted by libaio.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26764</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26763</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>dm-crypt: don't modify the data when using authenticated encryption
<br>
<br>It was said that authenticated encryption could produce invalid tag when
<br>the data that is being encrypted is modified [1]. So, fix this problem
by
<br>copying the data into the clone bio first and then encrypt them inside
the
<br>clone bio.
<br>
<br>This may reduce performance, but it is needed to prevent the user from
<br>corrupting the device by writing data with O_DIRECT and modifying them
at
<br>the same time.
<br>
<br>[1] <a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://lore.kernel.org/all/20240207004723.GA35324@sol.localdomain/T/</a>
</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26763</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26762</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>cxl/pci: Skip to handle RAS errors if CXL.mem device is detached
<br>
<br>The PCI AER model is an awkward fit for CXL error handling. While the
<br>expectation is that a PCI device can escalate to link reset to recover
<br>from an AER event, the same reset on CXL amounts to a surprise memory
<br>hotplug of massive amounts of memory.
<br>
<br>At present, the CXL error handler attempts some optimistic error
<br>handling to unbind the device from the cxl_mem driver after reaping some
<br>RAS register values. This results in a "hopeful" attempt to unplug the
<br>memory, but there is no guarantee that will succeed.
<br>
<br>A subsequent AER notification after the memdev unbind event can no
<br>longer assume the registers are mapped. Check for memdev bind before
<br>reaping status register values to avoid crashes of the form:
<br>
<br>BUG: unable to handle page fault for address: ffa00000195e9100
<br>#PF: supervisor read access in kernel mode
<br>#PF: error_code(0x0000) - not-present page
<br>[...]
<br>RIP: 0010:__cxl_handle_ras+0x30/0x110 [cxl_core]
<br>[...]
<br>Call Trace:
<br>&lt;TASK&gt;
<br>? __die+0x24/0x70
<br>? page_fault_oops+0x82/0x160
<br>? kernelmode_fixup_or_oops+0x84/0x110
<br>? exc_page_fault+0x113/0x170
<br>? asm_exc_page_fault+0x26/0x30
<br>? __pfx_dpc_reset_link+0x10/0x10
<br>? __cxl_handle_ras+0x30/0x110 [cxl_core]
<br>? find_cxl_port+0x59/0x80 [cxl_core]
<br>cxl_handle_rp_ras+0xbc/0xd0 [cxl_core]
<br>cxl_error_detected+0x6c/0xf0 [cxl_core]
<br>report_error_detected+0xc7/0x1c0
<br>pci_walk_bus+0x73/0x90
<br>pcie_do_recovery+0x23f/0x330
<br>
<br>Longer term, the unbind and PCI_ERS_RESULT_DISCONNECT behavior might
<br>need to be replaced with a new PCI_ERS_RESULT_PANIC.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26762</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26761</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>cxl/pci: Fix disabling memory if DVSEC CXL Range does not match a CFMWS
window
<br>
<br>The Linux CXL subsystem is built on the assumption that HPA == SPA.
<br>That is, the host physical address (HPA) the HDM decoder registers are
<br>programmed with are system physical addresses (SPA).
<br>
<br>During HDM decoder setup, the DVSEC CXL range registers (cxl-3.1,
<br>8.1.3.8) are checked if the memory is enabled and the CXL range is in
<br>a HPA window that is described in a CFMWS structure of the CXL host
<br>bridge (cxl-3.1, 9.18.1.3).
<br>
<br>Now, if the HPA is not an SPA, the CXL range does not match a CFMWS
<br>window and the CXL memory range will be disabled then. The HDM decoder
<br>stops working which causes system memory being disabled and further a
<br>system hang during HDM decoder initialization, typically when a CXL
<br>enabled kernel boots.
<br>
<br>Prevent a system hang and do not disable the HDM decoder if the
<br>decoder's CXL range is not found in a CFMWS window.
<br>
<br>Note the change only fixes a hardware hang, but does not implement
<br>HPA/SPA translation. Support for this can be added in a follow on
<br>patch series.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26761</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26760</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>scsi: target: pscsi: Fix bio_put() for error case
<br>
<br>As of commit 066ff571011d ("block: turn bio_kmalloc into a simple kmalloc
<br>wrapper"), a bio allocated by bio_kmalloc() must be freed by bio_uninit()
<br>and kfree(). That is not done properly for the error case, hitting WARN
and
<br>NULL pointer dereference in bio_free().</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26760</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26759</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>mm/swap: fix race when skipping swapcache
<br>
<br>When skipping swapcache for SWP_SYNCHRONOUS_IO, if two or more threads
<br>swapin the same entry at the same time, they get different pages (A, B).
<br>Before one thread (T0) finishes the swapin and installs page (A) to the
<br>PTE, another thread (T1) could finish swapin of page (B), swap_free the
<br>entry, then swap out the possibly modified page reusing the same entry.
<br>It breaks the pte_same check in (T0) because PTE value is unchanged,
<br>causing ABA problem. Thread (T0) will install a stalled page (A) into
the
<br>PTE and cause data corruption.
<br>
<br>One possible callstack is like this:
<br>
<br>CPU0 CPU1
<br>---- ----
<br>do_swap_page() do_swap_page() with same entry
<br>&lt;direct swapin path&gt; &lt;direct swapin path&gt;
<br>&lt;alloc page A&gt; &lt;alloc page B&gt;
<br>swap_read_folio() &lt;- read to page A swap_read_folio() &lt;- read to
page B
<br>&lt;slow on later locks or interrupt&gt; &lt;finished swapin first&gt;
<br>... set_pte_at()
<br>swap_free() &lt;- entry is free
<br>&lt;write to page B, now page A stalled&gt;
<br>&lt;swap out page B to same swap entry&gt;
<br>pte_same() &lt;- Check pass, PTE seems
<br>unchanged, but page A
<br>is stalled!
<br>swap_free() &lt;- page B content lost!
<br>set_pte_at() &lt;- staled page A installed!
<br>
<br>And besides, for ZRAM, swap_free() allows the swap device to discard the
<br>entry content, so even if page (B) is not modified, if swap_read_folio()
<br>on CPU0 happens later than swap_free() on CPU1, it may also cause data
<br>loss.
<br>
<br>To fix this, reuse swapcache_prepare which will pin the swap entry using
<br>the cache flag, and allow only one thread to swap it in, also prevent
any
<br>parallel code from putting the entry in the cache. Release the pin after
<br>PT unlocked.
<br>
<br>Racers just loop and wait since it's a rare and very short event. A
<br>schedule_timeout_uninterruptible(1) call is added to avoid repeated page
<br>faults wasting too much CPU, causing livelock or adding too much noise
to
<br>perf statistics. A similar livelock issue was described in commit
<br>029c4628b2eb ("mm: swap: get rid of livelock in swapin readahead")
<br>
<br>Reproducer:
<br>
<br>This race issue can be triggered easily using a well constructed
<br>reproducer and patched brd (with a delay in read path) [1]:
<br>
<br>With latest 6.8 mainline, race caused data loss can be observed easily:
<br>$ gcc -g -lpthread test-thread-swap-race.c &amp;&amp; ./a.out
<br>Polulating 32MB of memory region...
<br>Keep swapping out...
<br>Starting round 0...
<br>Spawning 65536 workers...
<br>32746 workers spawned, wait for done...
<br>Round 0: Error on 0x5aa00, expected 32746, got 32743, 3 data loss!
<br>Round 0: Error on 0x395200, expected 32746, got 32743, 3 data loss!
<br>Round 0: Error on 0x3fd000, expected 32746, got 32737, 9 data loss!
<br>Round 0 Failed, 15 data loss!
<br>
<br>This reproducer spawns multiple threads sharing the same memory region
<br>using a small swap device. Every two threads updates mapped pages one
by
<br>one in opposite direction trying to create a race, with one dedicated
<br>thread keep swapping out the data out using madvise.
<br>
<br>The reproducer created a reproduce rate of about once every 5 minutes,
so
<br>the race should be totally possible in production.
<br>
<br>After this patch, I ran the reproducer for over a few hundred rounds and
<br>no data loss observed.
<br>
<br>Performance overhead is minimal, microbenchmark swapin 10G from 32G
<br>zram:
<br>
<br>Before: 10934698 us
<br>After: 11157121 us
<br>Cached: 13155355 us (Dropping SWP_SYNCHRONOUS_IO flag)
<br>
<br>[<a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">kasong@tencent.com</a>:
v4]
<br>Link: <a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://lkml.kernel.org/r/20240219082040.7495-1-ryncsn@gmail.com</a>
</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26759</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26758</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>md: Don't ignore suspended array in md_check_recovery()
<br>
<br>mddev_suspend() never stop sync_thread, hence it doesn't make sense to
<br>ignore suspended array in md_check_recovery(), which might cause
<br>sync_thread can't be unregistered.
<br>
<br>After commit f52f5c71f3d4 ("md: fix stopping sync thread"), following
<br>hang can be triggered by test shell/<a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">integrity-caching.sh</a>:
<br>
<br>1) suspend the array:
<br>raid_postsuspend
<br>mddev_suspend
<br>
<br>2) stop the array:
<br>raid_dtr
<br>md_stop
<br>__md_stop_writes
<br>stop_sync_thread
<br>set_bit(MD_RECOVERY_INTR, &amp;mddev-&gt;recovery);
<br>md_wakeup_thread_directly(mddev-&gt;sync_thread);
<br>wait_event(..., !test_bit(MD_RECOVERY_RUNNING, &amp;mddev-&gt;recovery))
<br>
<br>3) sync thread done:
<br>md_do_sync
<br>set_bit(MD_RECOVERY_DONE, &amp;mddev-&gt;recovery);
<br>md_wakeup_thread(mddev-&gt;thread);
<br>
<br>4) daemon thread can't unregister sync thread:
<br>md_check_recovery
<br>if (mddev-&gt;suspended)
<br>return; -&gt; return directly
<br>md_read_sync_thread
<br>clear_bit(MD_RECOVERY_RUNNING, &amp;mddev-&gt;recovery);
<br>-&gt; MD_RECOVERY_RUNNING can't be cleared, hence step 2 hang;
<br>
<br>This problem is not just related to dm-raid, fix it by ignoring
<br>suspended array in md_check_recovery(). And follow up patches will
<br>improve dm-raid better to frozen sync thread during suspend.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26758</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26757</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>md: Don't ignore read-only array in md_check_recovery()
<br>
<br>Usually if the array is not read-write, md_check_recovery() won't
<br>register new sync_thread in the first place. And if the array is
<br>read-write and sync_thread is registered, md_set_readonly() will
<br>unregister sync_thread before setting the array read-only. md/raid
<br>follow this behavior hence there is no problem.
<br>
<br>After commit f52f5c71f3d4 ("md: fix stopping sync thread"), following
<br>hang can be triggered by test shell/<a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">integrity-caching.sh</a>:
<br>
<br>1) array is read-only. dm-raid update super block:
<br>rs_update_sbs
<br>ro = mddev-&gt;ro
<br>mddev-&gt;ro = 0
<br>-&gt; set array read-write
<br>md_update_sb
<br>
<br>2) register new sync thread concurrently.
<br>
<br>3) dm-raid set array back to read-only:
<br>rs_update_sbs
<br>mddev-&gt;ro = ro
<br>
<br>4) stop the array:
<br>raid_dtr
<br>md_stop
<br>stop_sync_thread
<br>set_bit(MD_RECOVERY_INTR, &amp;mddev-&gt;recovery);
<br>md_wakeup_thread_directly(mddev-&gt;sync_thread);
<br>wait_event(..., !test_bit(MD_RECOVERY_RUNNING, &amp;mddev-&gt;recovery))
<br>
<br>5) sync thread done:
<br>md_do_sync
<br>set_bit(MD_RECOVERY_DONE, &amp;mddev-&gt;recovery);
<br>md_wakeup_thread(mddev-&gt;thread);
<br>
<br>6) daemon thread can't unregister sync thread:
<br>md_check_recovery
<br>if (!md_is_rdwr(mddev) &amp;&amp;
<br>!test_bit(MD_RECOVERY_NEEDED, &amp;mddev-&gt;recovery))
<br>return;
<br>-&gt; -&gt; MD_RECOVERY_RUNNING can't be cleared, hence step 4 hang;
<br>
<br>The root cause is that dm-raid manipulate 'mddev-&gt;ro' by itself,
<br>however, dm-raid really should stop sync thread before setting the
<br>array read-only. Unfortunately, I need to read more code before I
<br>can refacter the handler of 'mddev-&gt;ro' in dm-raid, hence let's fix
<br>the problem the easy way for now to prevent dm-raid regression.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26757</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26756</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>md: Don't register sync_thread for reshape directly
<br>
<br>Currently, if reshape is interrupted, then reassemble the array will
<br>register sync_thread directly from pers-&gt;run(), in this case
<br>'MD_RECOVERY_RUNNING' is set directly, however, there is no guarantee
<br>that md_do_sync() will be executed, hence stop_sync_thread() will hang
<br>because 'MD_RECOVERY_RUNNING' can't be cleared.
<br>
<br>Last patch make sure that md_do_sync() will set MD_RECOVERY_DONE,
<br>however, following hang can still be triggered by dm-raid test
<br>shell/<a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">lvconvert-raid-reshape.sh</a> occasionally:
<br>
<br>[root@fedora ~]# cat /proc/1982/stack
<br>[&lt;0&gt;] stop_sync_thread+0x1ab/0x270 [md_mod]
<br>[&lt;0&gt;] md_frozen_sync_thread+0x5c/0xa0 [md_mod]
<br>[&lt;0&gt;] raid_presuspend+0x1e/0x70 [dm_raid]
<br>[&lt;0&gt;] dm_table_presuspend_targets+0x40/0xb0 [dm_mod]
<br>[&lt;0&gt;] __dm_destroy+0x2a5/0x310 [dm_mod]
<br>[&lt;0&gt;] dm_destroy+0x16/0x30 [dm_mod]
<br>[&lt;0&gt;] dev_remove+0x165/0x290 [dm_mod]
<br>[&lt;0&gt;] ctl_ioctl+0x4bb/0x7b0 [dm_mod]
<br>[&lt;0&gt;] dm_ctl_ioctl+0x11/0x20 [dm_mod]
<br>[&lt;0&gt;] vfs_ioctl+0x21/0x60
<br>[&lt;0&gt;] __x64_sys_ioctl+0xb9/0xe0
<br>[&lt;0&gt;] do_syscall_64+0xc6/0x230
<br>[&lt;0&gt;] entry_SYSCALL_64_after_hwframe+0x6c/0x74
<br>
<br>Meanwhile mddev-&gt;recovery is:
<br>MD_RECOVERY_RUNNING |
<br>MD_RECOVERY_INTR |
<br>MD_RECOVERY_RESHAPE |
<br>MD_RECOVERY_FROZEN
<br>
<br>Fix this problem by remove the code to register sync_thread directly
<br>from raid10 and raid5. And let md_check_recovery() to register
<br>sync_thread.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26756</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26755</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>md: Don't suspend the array for interrupted reshape
<br>
<br>md_start_sync() will suspend the array if there are spares that can be
<br>added or removed from conf, however, if reshape is still in progress,
<br>this won't happen at all or data will be corrupted(remove_and_add_spares
<br>won't be called from md_choose_sync_action for reshape), hence there is
<br>no need to suspend the array if reshape is not done yet.
<br>
<br>Meanwhile, there is a potential deadlock for raid456:
<br>
<br>1) reshape is interrupted;
<br>
<br>2) set one of the disk WantReplacement, and add a new disk to the array,
<br>however, recovery won't start until the reshape is finished;
<br>
<br>3) then issue an IO across reshpae position, this IO will wait for
<br>reshape to make progress;
<br>
<br>4) continue to reshape, then md_start_sync() found there is a spare disk
<br>that can be added to conf, mddev_suspend() is called;
<br>
<br>Step 4 and step 3 is waiting for each other, deadlock triggered. Noted
<br>this problem is found by code review, and it's not reporduced yet.
<br>
<br>Fix this porblem by don't suspend the array for interrupted reshape,
<br>this is safe because conf won't be changed until reshape is done.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26755</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26754</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>gtp: fix use-after-free and null-ptr-deref in gtp_genl_dump_pdp()
<br>
<br>The gtp_net_ops pernet operations structure for the subsystem must be
<br>registered before registering the generic netlink family.
<br>
<br>Syzkaller hit 'general protection fault in gtp_genl_dump_pdp' bug:
<br>
<br>general protection fault, probably for non-canonical address
<br>0xdffffc0000000002: 0000 [#1] PREEMPT SMP KASAN NOPTI
<br>KASAN: null-ptr-deref in range [0x0000000000000010-0x0000000000000017]
<br>CPU: 1 PID: 5826 Comm: gtp Not tainted 6.8.0-rc3-std-def-alt1 #1
<br>Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.0-alt1 04/01/2014
<br>RIP: 0010:gtp_genl_dump_pdp+0x1be/0x800 [gtp]
<br>Code: c6 89 c6 e8 64 e9 86 df 58 45 85 f6 0f 85 4e 04 00 00 e8 c5 ee 86
<br>df 48 8b 54 24 18 48 b8 00 00 00 00 00 fc ff df 48 c1 ea 03 &lt;80&gt;
<br>3c 02 00 0f 85 de 05 00 00 48 8b 44 24 18 4c 8b 30 4c 39 f0 74
<br>RSP: 0018:ffff888014107220 EFLAGS: 00010202
<br>RAX: dffffc0000000000 RBX: 0000000000000000 RCX: 0000000000000000
<br>RDX: 0000000000000002 RSI: 0000000000000000 RDI: 0000000000000000
<br>RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
<br>R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
<br>R13: ffff88800fcda588 R14: 0000000000000001 R15: 0000000000000000
<br>FS: 00007f1be4eb05c0(0000) GS:ffff88806ce80000(0000) knlGS:0000000000000000
<br>CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033
<br>CR2: 00007f1be4e766cf CR3: 000000000c33e000 CR4: 0000000000750ef0
<br>PKRU: 55555554
<br>Call Trace:
<br>&lt;TASK&gt;
<br>? show_regs+0x90/0xa0
<br>? die_addr+0x50/0xd0
<br>? exc_general_protection+0x148/0x220
<br>? asm_exc_general_protection+0x22/0x30
<br>? gtp_genl_dump_pdp+0x1be/0x800 [gtp]
<br>? __alloc_skb+0x1dd/0x350
<br>? <strong>pfx</strong>_alloc_skb+0x10/0x10
<br>genl_dumpit+0x11d/0x230
<br>netlink_dump+0x5b9/0xce0
<br>? lockdep_hardirqs_on_prepare+0x253/0x430
<br>? __pfx_netlink_dump+0x10/0x10
<br>? kasan_save_track+0x10/0x40
<br>? __kasan_kmalloc+0x9b/0xa0
<br>? genl_start+0x675/0x970
<br>__netlink_dump_start+0x6fc/0x9f0
<br>genl_family_rcv_msg_dumpit+0x1bb/0x2d0
<br>? __pfx_genl_family_rcv_msg_dumpit+0x10/0x10
<br>? genl_op_from_small+0x2a/0x440
<br>? cap_capable+0x1d0/0x240
<br>? __pfx_genl_start+0x10/0x10
<br>? __pfx_genl_dumpit+0x10/0x10
<br>? __pfx_genl_done+0x10/0x10
<br>? security_capable+0x9d/0xe0</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26754</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26753</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>crypto: virtio/akcipher - Fix stack overflow on memcpy
<br>
<br>sizeof(struct virtio_crypto_akcipher_session_para) is less than
<br>sizeof(struct virtio_crypto_op_ctrl_req::u), copying more bytes from
<br>stack variable leads stack overflow. Clang reports this issue by
<br>commands:
<br>make -j CC=clang-14 mrproper &gt;/dev/null 2&gt;&amp;1
<br>make -j O=/tmp/crypto-build CC=clang-14 allmodconfig &gt;/dev/null 2&gt;&amp;1
<br>make -j O=/tmp/crypto-build W=1 CC=clang-14 drivers/crypto/virtio/
<br>virtio_crypto_akcipher_algs.o</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26753</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26752</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>l2tp: pass correct message length to ip6_append_data
<br>
<br>l2tp_ip6_sendmsg needs to avoid accounting for the transport header
<br>twice when splicing more data into an already partially-occupied skbuff.
<br>
<br>To manage this, we check whether the skbuff contains data using
<br>skb_queue_empty when deciding how much data to append using
<br>ip6_append_data.
<br>
<br>However, the code which performed the calculation was incorrect:
<br>
<br>ulen = len + skb_queue_empty(&amp;sk-&gt;sk_write_queue) ? transhdrlen
: 0;
<br>
<br>...due to C operator precedence, this ends up setting ulen to
<br>transhdrlen for messages with a non-zero length, which results in
<br>corrupted packets on the wire.
<br>
<br>Add parentheses to correct the calculation in line with the original
<br>intent.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26752</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26751</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>ARM: ep93xx: Add terminator to gpiod_lookup_table
<br>
<br>Without the terminator, if a con_id is passed to gpio_find() that
<br>does not exist in the lookup table the function will not stop looping
<br>correctly, and eventually cause an oops.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26751</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26749</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>usb: cdns3: fixed memory use after free at cdns3_gadget_ep_disable()
<br>
<br>...
<br>cdns3_gadget_ep_free_request(&amp;priv_ep-&gt;endpoint, &amp;priv_req-&gt;request);
<br>list_del_init(&amp;priv_req-&gt;list);
<br>...
<br>
<br>'priv_req' actually free at cdns3_gadget_ep_free_request(). But
<br>list_del_init() use priv_req-&gt;list after it.
<br>
<br>[ 1542.642868][ T534] BUG: KFENCE: use-after-free read in __list_del_entry_valid+0x10/0xd4
<br>[ 1542.642868][ T534]
<br>[ 1542.653162][ T534] Use-after-free read at 0x000000009ed0ba99 (in kfence-#3):
<br>[ 1542.660311][ T534] __list_del_entry_valid+0x10/0xd4
<br>[ 1542.665375][ T534] cdns3_gadget_ep_disable+0x1f8/0x388 [cdns3]
<br>[ 1542.671571][ T534] usb_ep_disable+0x44/0xe4
<br>[ 1542.675948][ T534] ffs_func_eps_disable+0x64/0xc8
<br>[ 1542.680839][ T534] ffs_func_set_alt+0x74/0x368
<br>[ 1542.685478][ T534] ffs_func_disable+0x18/0x28
<br>
<br>Move list_del_init() before cdns3_gadget_ep_free_request() to resolve
this
<br>problem.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26749</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26748</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>usb: cdns3: fix memory double free when handle zero packet
<br>
<br>829 if (request-&gt;complete) {
<br>830 spin_unlock(&amp;priv_dev-&gt;lock);
<br>831 usb_gadget_giveback_request(&amp;priv_ep-&gt;endpoint,
<br>832 request);
<br>833 spin_lock(&amp;priv_dev-&gt;lock);
<br>834 }
<br>835
<br>836 if (request-&gt;buf == priv_dev-&gt;zlp_buf)
<br>837 cdns3_gadget_ep_free_request(&amp;priv_ep-&gt;endpoint, request);
<br>
<br>Driver append an additional zero packet request when queue a packet, which
<br>length mod max packet size is 0. When transfer complete, run to line 831,
<br>usb_gadget_giveback_request() will free this requestion. 836 condition
is
<br>true, so cdns3_gadget_ep_free_request() free this request again.
<br>
<br>Log:
<br>
<br>[ 1920.140696][ T150] BUG: KFENCE: use-after-free read in cdns3_gadget_giveback+0x134/0x2c0
[cdns3]
<br>[ 1920.140696][ T150]
<br>[ 1920.151837][ T150] Use-after-free read at 0x000000003d1cd10b (in kfence-#36):
<br>[ 1920.159082][ T150] cdns3_gadget_giveback+0x134/0x2c0 [cdns3]
<br>[ 1920.164988][ T150] cdns3_transfer_completed+0x438/0x5f8 [cdns3]
<br>
<br>Add check at line 829, skip call usb_gadget_giveback_request() if it is
<br>additional zero length packet request. Needn't call
<br>usb_gadget_giveback_request() because it is allocated in this driver.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26748</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26747</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>usb: roles: fix NULL pointer issue when put module's reference
<br>
<br>In current design, usb role class driver will get usb_role_switch parent's
<br>module reference after the user get usb_role_switch device and put the
<br>reference after the user put the usb_role_switch device. However, the
<br>parent device of usb_role_switch may be removed before the user put the
<br>usb_role_switch. If so, then, NULL pointer issue will be met when the
user
<br>put the parent module's reference.
<br>
<br>This will save the module pointer in structure of usb_role_switch. Then,
<br>we don't need to find module by iterating long relations.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26747</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26744</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>RDMA/srpt: Support specifying the srpt_service_guid parameter
<br>
<br>Make loading ib_srpt with this parameter set work. The current behavior
is
<br>that setting that parameter while loading the ib_srpt kernel module
<br>triggers the following kernel crash:
<br>
<br>BUG: kernel NULL pointer dereference, address: 0000000000000000
<br>Call Trace:
<br>&lt;TASK&gt;
<br>parse_one+0x18c/0x1d0
<br>parse_args+0xe1/0x230
<br>load_module+0x8de/0xa60
<br>init_module_from_file+0x8b/0xd0
<br>idempotent_init_module+0x181/0x240
<br>__x64_sys_finit_module+0x5a/0xb0
<br>do_syscall_64+0x5f/0xe0
<br>entry_SYSCALL_64_after_hwframe+0x6e/0x76</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26744</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26743</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>RDMA/qedr: Fix qedr_create_user_qp error flow
<br>
<br>Avoid the following warning by making sure to free the allocated
<br>resources in case that qedr_init_user_queue() fail.
<br>
<br>-----------[ cut here ]-----------
<br>WARNING: CPU: 0 PID: 143192 at drivers/infiniband/core/rdma_core.c:874
uverbs_destroy_ufile_hw+0xcf/0xf0 [ib_uverbs]
<br>Modules linked in: tls target_core_user uio target_core_pscsi target_core_file
target_core_iblock ib_srpt ib_srp scsi_transport_srp nfsd nfs_acl rpcsec_gss_krb5
auth_rpcgss nfsv4 dns_resolver nfs lockd grace fscache netfs 8021q garp
mrp stp llc ext4 mbcache jbd2 opa_vnic ib_umad ib_ipoib sunrpc rdma_ucm
ib_isert iscsi_target_mod target_core_mod ib_iser libiscsi scsi_transport_iscsi
rdma_cm iw_cm ib_cm hfi1 intel_rapl_msr intel_rapl_common mgag200 qedr
sb_edac drm_shmem_helper rdmavt x86_pkg_temp_thermal drm_kms_helper intel_powerclamp
ib_uverbs coretemp i2c_algo_bit kvm_intel dell_wmi_descriptor ipmi_ssif
sparse_keymap kvm ib_core rfkill syscopyarea sysfillrect video sysimgblt
irqbypass ipmi_si ipmi_devintf fb_sys_fops rapl iTCO_wdt mxm_wmi iTCO_vendor_support
intel_cstate pcspkr dcdbas intel_uncore ipmi_msghandler lpc_ich acpi_power_meter
mei_me mei fuse drm xfs libcrc32c qede sd_mod ahci libahci t10_pi sg crct10dif_pclmul
crc32_pclmul crc32c_intel qed libata tg3
<br>ghash_clmulni_intel megaraid_sas crc8 wmi [last unloaded: ib_srpt]
<br>CPU: 0 PID: 143192 Comm: fi_rdm_tagged_p Kdump: loaded Not tainted 5.14.0-408.el9.x86_64
#1
<br>Hardware name: Dell Inc. PowerEdge R430/03XKDV, BIOS 2.14.0 01/25/2022
<br>RIP: 0010:uverbs_destroy_ufile_hw+0xcf/0xf0 [ib_uverbs]
<br>Code: 5d 41 5c 41 5d 41 5e e9 0f 26 1b dd 48 89 df e8 67 6a ff ff 49 8b
86 10 01 00 00 48 85 c0 74 9c 4c 89 e7 e8 83 c0 cb dd eb 92 &lt;0f&gt;
0b eb be 0f 0b be 04 00 00 00 48 89 df e8 8e f5 ff ff e9 6d ff
<br>RSP: 0018:ffffb7c6cadfbc60 EFLAGS: 00010286
<br>RAX: ffff8f0889ee3f60 RBX: ffff8f088c1a5200 RCX: 00000000802a0016
<br>RDX: 00000000802a0017 RSI: 0000000000000001 RDI: ffff8f0880042600
<br>RBP: 0000000000000001 R08: 0000000000000001 R09: 0000000000000000
<br>R10: ffff8f11fffd5000 R11: 0000000000039000 R12: ffff8f0d5b36cd80
<br>R13: ffff8f088c1a5250 R14: ffff8f1206d91000 R15: 0000000000000000
<br>FS: 0000000000000000(0000) GS:ffff8f11d7c00000(0000) knlGS:0000000000000000
<br>CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033
<br>CR2: 0000147069200e20 CR3: 00000001c7210002 CR4: 00000000001706f0
<br>Call Trace:
<br>&lt;TASK&gt;
<br>? show_trace_log_lvl+0x1c4/0x2df
<br>? show_trace_log_lvl+0x1c4/0x2df
<br>? ib_uverbs_close+0x1f/0xb0 [ib_uverbs]
<br>? uverbs_destroy_ufile_hw+0xcf/0xf0 [ib_uverbs]
<br>? __warn+0x81/0x110
<br>? uverbs_destroy_ufile_hw+0xcf/0xf0 [ib_uverbs]
<br>? report_bug+0x10a/0x140
<br>? handle_bug+0x3c/0x70
<br>? exc_invalid_op+0x14/0x70
<br>? asm_exc_invalid_op+0x16/0x20
<br>? uverbs_destroy_ufile_hw+0xcf/0xf0 [ib_uverbs]
<br>ib_uverbs_close+0x1f/0xb0 [ib_uverbs]
<br>__fput+0x94/0x250
<br>task_work_run+0x5c/0x90
<br>do_exit+0x270/0x4a0
<br>do_group_exit+0x2d/0x90
<br>get_signal+0x87c/0x8c0
<br>arch_do_signal_or_restart+0x25/0x100
<br>? ib_uverbs_ioctl+0xc2/0x110 [ib_uverbs]
<br>exit_to_user_mode_loop+0x9c/0x130
<br>exit_to_user_mode_prepare+0xb6/0x100
<br>syscall_exit_to_user_mode+0x12/0x40
<br>do_syscall_64+0x69/0x90
<br>? syscall_exit_work+0x103/0x130
<br>? syscall_exit_to_user_mode+0x22/0x40
<br>? do_syscall_64+0x69/0x90
<br>? syscall_exit_work+0x103/0x130
<br>? syscall_exit_to_user_mode+0x22/0x40
<br>? do_syscall_64+0x69/0x90
<br>? do_syscall_64+0x69/0x90
<br>? common_interrupt+0x43/0xa0
<br>entry_SYSCALL_64_after_hwframe+0x72/0xdc
<br>RIP: 0033:0x1470abe3ec6b
<br>Code: Unable to access opcode bytes at RIP 0x1470abe3ec41.
<br>RSP: 002b:00007fff13ce9108 EFLAGS: 00000246 ORIG_RAX: 0000000000000010
<br>RAX: fffffffffffffffc RBX: 00007fff13ce9218 RCX: 00001470abe3ec6b
<br>RDX: 00007fff13ce9200 RSI: 00000000c0181b01 RDI: 0000000000000004
<br>RBP: 00007fff13ce91e0 R08: 0000558d9655da10 R09: 0000558d9655dd00
<br>R10: 00007fff13ce95c0 R11: 0000000000000246 R12: 00007fff13ce9358
<br>R13: 0000000000000013 R14: 0000558d9655db50 R15: 00007fff13ce9470
<br>&lt;/TASK&gt;
<br>--[ end trace 888a9b92e04c5c97 ]--</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26743</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26742</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>scsi: smartpqi: Fix disable_managed_interrupts
<br>
<br>Correct blk-mq registration issue with module parameter
<br>disable_managed_interrupts enabled.
<br>
<br>When we turn off the default PCI_IRQ_AFFINITY flag, the driver needs to
<br>register with blk-mq using blk_mq_map_queues(). The driver is currently
<br>calling blk_mq_pci_map_queues() which results in a stack trace and possibly
<br>undefined behavior.
<br>
<br>Stack Trace:
<br>[ 7.860089] scsi host2: smartpqi
<br>[ 7.871934] WARNING: CPU: 0 PID: 238 at block/blk-mq-pci.c:52 blk_mq_pci_map_queues+0xca/0xd0
<br>[ 7.889231] Modules linked in: sd_mod t10_pi sg uas smartpqi(+) crc32c_intel
scsi_transport_sas usb_storage dm_mirror dm_region_hash dm_log dm_mod ipmi_devintf
ipmi_msghandler fuse
<br>[ 7.924755] CPU: 0 PID: 238 Comm: kworker/0:3 Not tainted 4.18.0-372.88.1.el8_6_smartpqi_test.x86_64
#1
<br>[ 7.944336] Hardware name: HPE ProLiant DL380 Gen10/ProLiant DL380 Gen10,
BIOS U30 03/08/2022
<br>[ 7.963026] Workqueue: events work_for_cpu_fn
<br>[ 7.978275] RIP: 0010:blk_mq_pci_map_queues+0xca/0xd0
<br>[ 7.978278] Code: 48 89 de 89 c7 e8 f6 0f 4f 00 3b 05 c4 b7 8e 01 72 e1
5b 31 c0 5d 41 5c 41 5d 41 5e 41 5f e9 7d df 73 00 31 c0 e9 76 df 73 00
&lt;0f&gt; 0b eb bc 90 90 0f 1f 44 00 00 41 57 49 89 ff 41 56 41 55 41
54
<br>[ 7.978280] RSP: 0018:ffffa95fc3707d50 EFLAGS: 00010216
<br>[ 7.978283] RAX: 00000000ffffffff RBX: 0000000000000000 RCX: 0000000000000010
<br>[ 7.978284] RDX: 0000000000000004 RSI: 0000000000000000 RDI: ffff9190c32d4310
<br>[ 7.978286] RBP: 0000000000000000 R08: ffffa95fc3707d38 R09: ffff91929b81ac00
<br>[ 7.978287] R10: 0000000000000001 R11: ffffa95fc3707ac0 R12: 0000000000000000
<br>[ 7.978288] R13: ffff9190c32d4000 R14: 00000000ffffffff R15: ffff9190c4c950a8
<br>[ 7.978290] FS: 0000000000000000(0000) GS:ffff9193efc00000(0000) knlGS:0000000000000000
<br>[ 7.978292] CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033
<br>[ 8.172814] CR2: 000055d11166c000 CR3: 00000002dae10002 CR4: 00000000007706f0
<br>[ 8.172816] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
<br>[ 8.172817] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
<br>[ 8.172818] PKRU: 55555554
<br>[ 8.172819] Call Trace:
<br>[ 8.172823] blk_mq_alloc_tag_set+0x12e/0x310
<br>[ 8.264339] scsi_add_host_with_dma.cold.9+0x30/0x245
<br>[ 8.279302] pqi_ctrl_init+0xacf/0xc8e [smartpqi]
<br>[ 8.294085] ? pqi_pci_probe+0x480/0x4c8 [smartpqi]
<br>[ 8.309015] pqi_pci_probe+0x480/0x4c8 [smartpqi]
<br>[ 8.323286] local_pci_probe+0x42/0x80
<br>[ 8.337855] work_for_cpu_fn+0x16/0x20
<br>[ 8.351193] process_one_work+0x1a7/0x360
<br>[ 8.364462] ? create_worker+0x1a0/0x1a0
<br>[ 8.379252] worker_thread+0x1ce/0x390
<br>[ 8.392623] ? create_worker+0x1a0/0x1a0
<br>[ 8.406295] kthread+0x10a/0x120
<br>[ 8.418428] ? set_kthread_struct+0x50/0x50
<br>[ 8.431532] ret_from_fork+0x1f/0x40
<br>[ 8.444137] ---[ end trace 1bf0173d39354506 ]---</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26742</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26741</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>dccp/tcp: Unhash sk from ehash for tb2 alloc failure after check_estalblished().
<br>
<br>syzkaller reported a warning [0] in inet_csk_destroy_sock() with no
<br>repro.
<br>
<br>WARN_ON(inet_sk(sk)-&gt;inet_num &amp;&amp; !inet_csk(sk)-&gt;icsk_bind_hash);
<br>
<br>However, the syzkaller's log hinted that connect() failed just before
<br>the warning due to FAULT_INJECTION. [1]
<br>
<br>When connect() is called for an unbound socket, we search for an
<br>available ephemeral port. If a bhash bucket exists for the port, we
<br>call __inet_check_established() or __inet6_check_established() to check
<br>if the bucket is reusable.
<br>
<br>If reusable, we add the socket into ehash and set inet_sk(sk)-&gt;inet_num.
<br>
<br>Later, we look up the corresponding bhash2 bucket and try to allocate
<br>it if it does not exist.
<br>
<br>Although it rarely occurs in real use, if the allocation fails, we must
<br>revert the changes by check_established(). Otherwise, an unconnected
<br>socket could illegally occupy an ehash entry.
<br>
<br>Note that we do not put tw back into ehash because sk might have
<br>already responded to a packet for tw and it would be better to free
<br>tw earlier under such memory presure.
<br>
<br>[0]:
<br>WARNING: CPU: 0 PID: 350830 at net/ipv4/inet_connection_sock.c:1193 inet_csk_destroy_sock
(net/ipv4/inet_connection_sock.c:1193)
<br>Modules linked in:
<br>Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS <a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">rel-1.16.0-0-gd239552ce722-prebuilt.qemu.org</a> 04/01/2014
<br>RIP: 0010:inet_csk_destroy_sock (net/ipv4/inet_connection_sock.c:1193)
<br>Code: 41 5c 41 5d 41 5e e9 2d 4a 3d fd e8 28 4a 3d fd 48 89 ef e8 f0 cd
7d ff 5b 5d 41 5c 41 5d 41 5e e9 13 4a 3d fd e8 0e 4a 3d fd &lt;0f&gt;
0b e9 61 fe ff ff e8 02 4a 3d fd 4c 89 e7 be 03 00 00 00 e8 05
<br>RSP: 0018:ffffc9000b21fd38 EFLAGS: 00010293
<br>RAX: 0000000000000000 RBX: 0000000000009e78 RCX: ffffffff840bae40
<br>RDX: ffff88806e46c600 RSI: ffffffff840bb012 RDI: ffff88811755cca8
<br>RBP: ffff88811755c880 R08: 0000000000000003 R09: 0000000000000000
<br>R10: 0000000000009e78 R11: 0000000000000000 R12: ffff88811755c8e0
<br>R13: ffff88811755c892 R14: ffff88811755c918 R15: 0000000000000000
<br>FS: 00007f03e5243800(0000) GS:ffff88811ae00000(0000) knlGS:0000000000000000
<br>CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033
<br>CR2: 0000001b32f21000 CR3: 0000000112ffe001 CR4: 0000000000770ef0
<br>PKRU: 55555554
<br>Call Trace:
<br>&lt;TASK&gt;
<br>? inet_csk_destroy_sock (net/ipv4/inet_connection_sock.c:1193)
<br>dccp_close (net/dccp/proto.c:1078)
<br>inet_release (net/ipv4/af_inet.c:434)
<br>__sock_release (net/socket.c:660)
<br>sock_close (net/socket.c:1423)
<br>__fput (fs/file_table.c:377)
<br>__fput_sync (fs/file_table.c:462)
<br>__x64_sys_close (fs/open.c:1557 fs/open.c:1539 fs/open.c:1539)
<br>do_syscall_64 (arch/x86/entry/common.c:52 arch/x86/entry/common.c:83)
<br>entry_SYSCALL_64_after_hwframe (arch/x86/entry/entry_64.S:129)
<br>RIP: 0033:0x7f03e53852bb
<br>Code: 03 00 00 00 0f 05 48 3d 00 f0 ff ff 77 41 c3 48 83 ec 18 89 7c 24
0c e8 43 c9 f5 ff 8b 7c 24 0c 41 89 c0 b8 03 00 00 00 0f 05 &lt;48&gt;
3d 00 f0 ff ff 77 35 44 89 c7 89 44 24 0c e8 a1 c9 f5 ff 8b 44
<br>RSP: 002b:00000000005dfba0 EFLAGS: 00000293 ORIG_RAX: 0000000000000003
<br>RAX: ffffffffffffffda RBX: 0000000000000004 RCX: 00007f03e53852bb
<br>RDX: 0000000000000002 RSI: 0000000000000002 RDI: 0000000000000003
<br>RBP: 0000000000000000 R08: 0000000000000000 R09: 000000000000167c
<br>R10: 0000000008a79680 R11: 0000000000000293 R12: 00007f03e4e43000
<br>R13: 00007f03e4e43170 R14: 00007f03e4e43178 R15: 00007f03e4e43170
<br>&lt;/TASK&gt;
<br>
<br>[1]:
<br>FAULT_INJECTION: forcing a failure.
<br>name failslab, interval 1, probability 0, space 0, times 0
<br>CPU: 0 PID: 350833 Comm: syz-executor.1 Not tainted 6.7.0-12272-g2121c43f88f5
#9
<br>Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS <a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">rel-1.16.0-0-gd239552ce722-prebuilt.qemu.org</a> 04/01/2014
<br>Call Trace:
<br>&lt;TASK&gt;
<br>dump_stack_lvl (lib/dump_stack.c:107 (discriminator 1))
<br>should_fail_ex (lib/fault-inject.c:52 lib/fault-inject.c:153)
<br>should_failslab (mm/slub.c:3748)
<br>kmem_cache_alloc (mm/slub.c:3763 mm/slub.c:3842 mm/slub.c:3867)
<br>inet_bind2_bucket_create
<br>---truncated---</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26741</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26740</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>net/sched: act_mirred: use the backlog for mirred ingress
<br>
<br>The test Davide added in commit ca22da2fbd69 ("act_mirred: use the backlog
<br>for nested calls to mirred ingress") hangs our testing VMs every 10 or
so
<br>runs, with the familiar tcp_v4_rcv -&gt; tcp_v4_rcv deadlock reported
by
<br>lockdep.
<br>
<br>The problem as previously described by Davide (see Link) is that
<br>if we reverse flow of traffic with the redirect (egress -&gt; ingress)
<br>we may reach the same socket which generated the packet. And we may
<br>still be holding its socket lock. The common solution to such deadlocks
<br>is to put the packet in the Rx backlog, rather than run the Rx path
<br>inline. Do that for all egress -&gt; ingress reversals, not just once
<br>we started to nest mirred calls.
<br>
<br>In the past there was a concern that the backlog indirection will
<br>lead to loss of error reporting / less accurate stats. But the current
<br>workaround does not seem to address the issue.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26740</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26739</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>net/sched: act_mirred: don't override retval if we already lost the skb
<br>
<br>If we're redirecting the skb, and haven't called tcf_mirred_forward(),
<br>yet, we need to tell the core to drop the skb by setting the retcode
<br>to SHOT. If we have called tcf_mirred_forward(), however, the skb
<br>is out of our hands and returning SHOT will lead to UaF.
<br>
<br>Move the retval override to the error path which actually need it.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26739</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26738</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>powerpc/pseries/iommu: DLPAR add doesn't completely initialize pci_controller
<br>
<br>When a PCI device is dynamically added, the kernel oopses with a NULL
<br>pointer dereference:
<br>
<br>BUG: Kernel NULL pointer dereference on read at 0x00000030
<br>Faulting instruction address: 0xc0000000006bbe5c
<br>Oops: Kernel access of bad area, sig: 11 [#1]
<br>LE PAGE_SIZE=64K MMU=Radix SMP NR_CPUS=2048 NUMA pSeries
<br>Modules linked in: rpadlpar_io rpaphp rpcsec_gss_krb5 auth_rpcgss nfsv4
dns_resolver nfs lockd grace fscache netfs xsk_diag bonding nft_compat
nf_tables nfnetlink rfkill binfmt_misc dm_multipath rpcrdma sunrpc rdma_ucm
ib_srpt ib_isert iscsi_target_mod target_core_mod ib_umad ib_iser libiscsi
scsi_transport_iscsi ib_ipoib rdma_cm iw_cm ib_cm mlx5_ib ib_uverbs ib_core
pseries_rng drm drm_panel_orientation_quirks xfs libcrc32c mlx5_core mlxfw
sd_mod t10_pi sg tls ibmvscsi ibmveth scsi_transport_srp vmx_crypto pseries_wdt
psample dm_mirror dm_region_hash dm_log dm_mod fuse
<br>CPU: 17 PID: 2685 Comm: drmgr Not tainted 6.7.0-203405+ #66
<br>Hardware name: IBM,9080-HEX POWER10 (raw) 0x800200 0xf000006 of:IBM,FW1060.00
(NH1060_008) hv:phyp pSeries
<br>NIP: c0000000006bbe5c LR: c000000000a13e68 CTR: c0000000000579f8
<br>REGS: c00000009924f240 TRAP: 0300 Not tainted (6.7.0-203405+)
<br>MSR: 8000000000009033 &lt;SF,EE,ME,IR,DR,RI,LE&gt; CR: 24002220 XER: 20040006
<br>CFAR: c000000000a13e64 DAR: 0000000000000030 DSISR: 40000000 IRQMASK:
0
<br>...
<br>NIP sysfs_add_link_to_group+0x34/0x94
<br>LR iommu_device_link+0x5c/0x118
<br>Call Trace:
<br>iommu_init_device+0x26c/0x318 (unreliable)
<br>iommu_device_link+0x5c/0x118
<br>iommu_init_device+0xa8/0x318
<br>iommu_probe_device+0xc0/0x134
<br>iommu_bus_notifier+0x44/0x104
<br>notifier_call_chain+0xb8/0x19c
<br>blocking_notifier_call_chain+0x64/0x98
<br>bus_notify+0x50/0x7c
<br>device_add+0x640/0x918
<br>pci_device_add+0x23c/0x298
<br>of_create_pci_dev+0x400/0x884
<br>of_scan_pci_dev+0x124/0x1b0
<br>__of_scan_bus+0x78/0x18c
<br>pcibios_scan_phb+0x2a4/0x3b0
<br>init_phb_dynamic+0xb8/0x110
<br>dlpar_add_slot+0x170/0x3b8 [rpadlpar_io]
<br>add_slot_store.part.0+0xb4/0x130 [rpadlpar_io]
<br>kobj_attr_store+0x2c/0x48
<br>sysfs_kf_write+0x64/0x78
<br>kernfs_fop_write_iter+0x1b0/0x290
<br>vfs_write+0x350/0x4a0
<br>ksys_write+0x84/0x140
<br>system_call_exception+0x124/0x330
<br>system_call_vectored_common+0x15c/0x2ec
<br>
<br>Commit a940904443e4 ("powerpc/iommu: Add iommu_ops to report capabilities
<br>and allow blocking domains") broke DLPAR add of PCI devices.
<br>
<br>The above added iommu_device structure to pci_controller. During
<br>system boot, PCI devices are discovered and this newly added iommu_device
<br>structure is initialized by a call to iommu_device_register().
<br>
<br>During DLPAR add of a PCI device, a new pci_controller structure is
<br>allocated but there are no calls made to iommu_device_register()
<br>interface.
<br>
<br>Fix is to register the iommu device during DLPAR add as well.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26738</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26737</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>bpf: Fix racing between bpf_timer_cancel_and_free and bpf_timer_cancel
<br>
<br>The following race is possible between bpf_timer_cancel_and_free
<br>and bpf_timer_cancel. It will lead a UAF on the timer-&gt;timer.
<br>
<br>bpf_timer_cancel();
<br>\tspin_lock();
<br>\tt = timer-&gt;time;
<br>\tspin_unlock();
<br>
<br>\t\t\t\t\tbpf_timer_cancel_and_free();
<br>\t\t\t\t\t\tspin_lock();
<br>\t\t\t\t\t\tt = timer-&gt;timer;
<br>\t\t\t\t\t\ttimer-&gt;timer = NULL;
<br>\t\t\t\t\t\tspin_unlock();
<br>\t\t\t\t\t\thrtimer_cancel(&amp;t-&gt;timer);
<br>\t\t\t\t\t\tkfree(t);
<br>
<br>\t/* UAF on t */
<br>\thrtimer_cancel(&amp;t-&gt;timer);
<br>
<br>In bpf_timer_cancel_and_free, this patch frees the timer-&gt;timer
<br>after a rcu grace period. This requires a rcu_head addition
<br>to the "struct bpf_hrtimer". Another kfree(t) happens in bpf_timer_init,
<br>this does not need a kfree_rcu because it is still under the
<br>spin_lock and timer-&gt;timer has not been visible by others yet.
<br>
<br>In bpf_timer_cancel, rcu_read_lock() is added because this helper
<br>can be used in a non rcu critical section context (e.g. from
<br>a sleepable bpf prog). Other timer-&gt;timer usages in helpers.c
<br>have been audited, bpf_timer_cancel() is the only place where
<br>timer-&gt;timer is used outside of the spin_lock.
<br>
<br>Another solution considered is to mark a t-&gt;flag in bpf_timer_cancel
<br>and clear it after hrtimer_cancel() is done. In bpf_timer_cancel_and_free,
<br>it busy waits for the flag to be cleared before kfree(t). This patch
<br>goes with a straight forward solution and frees timer-&gt;timer after
<br>a rcu grace period.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26737</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26736</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>afs: Increase buffer size in afs_update_volume_status()
<br>
<br>The max length of volume-&gt;vid value is 20 characters.
<br>So increase idbuf[] size up to 24 to avoid overflow.
<br>
<br>Found by Linux Verification Center (<a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">linuxtesting.org</a>) with SVACE.
<br>
<br>[DH: Actually, it's 20 + NUL, so increase it to 24 and use snprintf()]</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26736</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26735</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>ipv6: sr: fix possible use-after-free and null-ptr-deref
<br>
<br>The pernet operations structure for the subsystem must be registered
<br>before registering the generic netlink family.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26735</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26734</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>devlink: fix possible use-after-free and memory leaks in devlink_init()
<br>
<br>The pernet operations structure for the subsystem must be registered
<br>before registering the generic netlink family.
<br>
<br>Make an unregister in case of unsuccessful registration.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26734</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26733</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>arp: Prevent overflow in arp_req_get().
<br>
<br>syzkaller reported an overflown write in arp_req_get(). [0]
<br>
<br>When ioctl(SIOCGARP) is issued, arp_req_get() looks up an neighbour
<br>entry and copies neigh-&gt;ha to struct arpreq.arp_<a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">ha.sa</a>_data.
<br>
<br>The arp_ha here is struct sockaddr, not struct sockaddr_storage, so
<br>the sa_data buffer is just 14 bytes.
<br>
<br>In the splat below, 2 bytes are overflown to the next int field,
<br>arp_flags. We initialise the field just after the memcpy(), so it's
<br>not a problem.
<br>
<br>However, when dev-&gt;addr_len is greater than 22 (e.g. MAX_ADDR_LEN),
<br>arp_netmask is overwritten, which could be set as htonl(0xFFFFFFFFUL)
<br>in arp_ioctl() before calling arp_req_get().
<br>
<br>To avoid the overflow, let's limit the max length of memcpy().
<br>
<br>Note that commit b5f0de6df6dc ("net: dev: Convert sa_data to flexible
<br>array in struct sockaddr") just silenced syzkaller.
<br>
<br>[0]:
<br>memcpy: detected field-spanning write (size 16) of single field "r-&gt;arp_
<a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">ha.sa</a>_data" at net/ipv4/arp.c:1128 (size 14)
<br>WARNING: CPU: 0 PID: 144638 at net/ipv4/arp.c:1128 arp_req_get+0x411/0x4a0
net/ipv4/arp.c:1128
<br>Modules linked in:
<br>CPU: 0 PID: 144638 Comm: syz-executor.4 Not tainted 6.1.74 #31
<br>Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.0-debian-1.16.0-5
04/01/2014
<br>RIP: 0010:arp_req_get+0x411/0x4a0 net/ipv4/arp.c:1128
<br>Code: fd ff ff e8 41 42 de fb b9 0e 00 00 00 4c 89 fe 48 c7 c2 20 6d ab
87 48 c7 c7 80 6d ab 87 c6 05 25 af 72 04 01 e8 5f 8d ad fb &lt;0f&gt;
0b e9 6c fd ff ff e8 13 42 de fb be 03 00 00 00 4c 89 e7 e8 a6
<br>RSP: 0018:ffffc900050b7998 EFLAGS: 00010286
<br>RAX: 0000000000000000 RBX: ffff88803a815000 RCX: 0000000000000000
<br>RDX: 0000000000000000 RSI: ffffffff8641a44a RDI: 0000000000000001
<br>RBP: ffffc900050b7a98 R08: 0000000000000001 R09: 0000000000000000
<br>R10: 0000000000000000 R11: 203a7970636d656d R12: ffff888039c54000
<br>R13: 1ffff92000a16f37 R14: ffff88803a815084 R15: 0000000000000010
<br>FS: 00007f172bf306c0(0000) GS:ffff88805aa00000(0000) knlGS:0000000000000000
<br>CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033
<br>CR2: 00007f172b3569f0 CR3: 0000000057f12005 CR4: 0000000000770ef0
<br>DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
<br>DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
<br>PKRU: 55555554
<br>Call Trace:
<br>&lt;TASK&gt;
<br>arp_ioctl+0x33f/0x4b0 net/ipv4/arp.c:1261
<br>inet_ioctl+0x314/0x3a0 net/ipv4/af_inet.c:981
<br>sock_do_ioctl+0xdf/0x260 net/socket.c:1204
<br>sock_ioctl+0x3ef/0x650 net/socket.c:1321
<br>vfs_ioctl fs/ioctl.c:51 [inline]
<br>__do_sys_ioctl fs/ioctl.c:870 [inline]
<br>__se_sys_ioctl fs/ioctl.c:856 [inline]
<br>__x64_sys_ioctl+0x18e/0x220 fs/ioctl.c:856
<br>do_syscall_x64 arch/x86/entry/common.c:51 [inline]
<br>do_syscall_64+0x37/0x90 arch/x86/entry/common.c:81
<br>entry_SYSCALL_64_after_hwframe+0x64/0xce
<br>RIP: 0033:0x7f172b262b8d
<br>Code: 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 00 f3 0f 1e fa 48 89 f8 48 89
f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 &lt;48&gt;
3d 01 f0 ff ff 73 01 c3 48 c7 c1 b8 ff ff ff f7 d8 64 89 01 48
<br>RSP: 002b:00007f172bf300b8 EFLAGS: 00000246 ORIG_RAX: 0000000000000010
<br>RAX: ffffffffffffffda RBX: 00007f172b3abf80 RCX: 00007f172b262b8d
<br>RDX: 0000000020000000 RSI: 0000000000008954 RDI: 0000000000000003
<br>RBP: 00007f172b2d3493 R08: 0000000000000000 R09: 0000000000000000
<br>R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000
<br>R13: 000000000000000b R14: 00007f172b3abf80 R15: 00007f172bf10000
<br>&lt;/TASK&gt;</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26733</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26731</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>bpf, sockmap: Fix NULL pointer dereference in sk_psock_verdict_data_ready()
<br>
<br>syzbot reported the following NULL pointer dereference issue [1]:
<br>
<br>BUG: kernel NULL pointer dereference, address: 0000000000000000
<br>[...]
<br>RIP: 0010:0x0
<br>[...]
<br>Call Trace:
<br>&lt;TASK&gt;
<br>sk_psock_verdict_data_ready+0x232/0x340 net/core/skmsg.c:1230
<br>unix_stream_sendmsg+0x9b4/0x1230 net/unix/af_unix.c:2293
<br>sock_sendmsg_nosec net/socket.c:730 [inline]
<br>__sock_sendmsg+0x221/0x270 net/socket.c:745
<br>____sys_sendmsg+0x525/0x7d0 net/socket.c:2584
<br>___sys_sendmsg net/socket.c:2638 [inline]
<br>__sys_sendmsg+0x2b0/0x3a0 net/socket.c:2667
<br>do_syscall_64+0xf9/0x240
<br>entry_SYSCALL_64_after_hwframe+0x6f/0x77
<br>
<br>If sk_psock_verdict_data_ready() and sk_psock_stop_verdict() are called
<br>concurrently, psock-&gt;saved_data_ready can be NULL, causing the above
issue.
<br>
<br>This patch fixes this issue by calling the appropriate data ready function
<br>using the sk_psock_data_ready() helper and protecting it from concurrency
<br>with sk-&gt;sk_callback_lock.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26731</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26730</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>hwmon: (nct6775) Fix access to temperature configuration registers
<br>
<br>The number of temperature configuration registers does
<br>not always match the total number of temperature registers.
<br>This can result in access errors reported if KASAN is enabled.
<br>
<br>BUG: KASAN: global-out-of-bounds in nct6775_probe+0x5654/0x6fe9 nct6775_core</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26730</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26729</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>drm/amd/display: Fix potential null pointer dereference in dc_dmub_srv
<br>
<br>Fixes potential null pointer dereference warnings in the
<br>dc_dmub_srv_cmd_list_queue_execute() and dc_dmub_srv_is_hw_pwr_up()
<br>functions.
<br>
<br>In both functions, the 'dc_dmub_srv' variable was being dereferenced
<br>before it was checked for null. This could lead to a null pointer
<br>dereference if 'dc_dmub_srv' is null. The fix is to check if
<br>'dc_dmub_srv' is null before dereferencing it.
<br>
<br>Thus moving the null checks for 'dc_dmub_srv' to the beginning of the
<br>functions to ensure that 'dc_dmub_srv' is not null when it is
<br>dereferenced.
<br>
<br>Found by smatch &amp; thus fixing the below:
<br>drivers/gpu/drm/amd/amdgpu/../display/dc/dc_dmub_srv.c:133 dc_dmub_srv_cmd_list_queue_execute()
warn: variable dereferenced before check 'dc_dmub_srv' (see line 128)
<br>drivers/gpu/drm/amd/amdgpu/../display/dc/dc_dmub_srv.c:1167 dc_dmub_srv_is_hw_pwr_up()
warn: variable dereferenced before check 'dc_dmub_srv' (see line 1164)</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26729</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26728</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>drm/amd/display: fix null-pointer dereference on edid reading
<br>
<br>Use i2c adapter when there isn't aux_mode in dc_link to fix a
<br>null-pointer derefence that happens when running
<br>igt@kms_force_connector_basic in a system with DCN2.1 and HDMI connector
<br>detected as below:
<br>
<br>[ +0.178146] BUG: kernel NULL pointer dereference, address: 00000000000004c0
<br>[ +0.000010] #PF: supervisor read access in kernel mode
<br>[ +0.000005] #PF: error_code(0x0000) - not-present page
<br>[ +0.000004] PGD 0 P4D 0
<br>[ +0.000006] Oops: 0000 [#1] PREEMPT SMP NOPTI
<br>[ +0.000006] CPU: 15 PID: 2368 Comm: kms_force_conne Not tainted 6.5.0-asdn+
#152
<br>[ +0.000005] Hardware name: HP HP ENVY x360 Convertible 13-ay1xxx/8929,
BIOS F.01 07/14/2021
<br>[ +0.000004] RIP: 0010:i2c_transfer+0xd/0x100
<br>[ +0.000011] Code: ea fc ff ff 66 0f 1f 84 00 00 00 00 00 90 90 90 90
90 90 90 90 90 90 90 90 90 90 90 90 f3 0f 1e fa 0f 1f 44 00 00 41 54 55
53 &lt;48&gt; 8b 47 10 48 89 fb 48 83 38 00 0f 84 b3 00 00 00 83 3d 2f
80 16
<br>[ +0.000004] RSP: 0018:ffff9c4f89c0fad0 EFLAGS: 00010246
<br>[ +0.000005] RAX: 0000000000000000 RBX: 0000000000000005 RCX: 0000000000000080
<br>[ +0.000003] RDX: 0000000000000002 RSI: ffff9c4f89c0fb20 RDI: 00000000000004b0
<br>[ +0.000003] RBP: ffff9c4f89c0fb80 R08: 0000000000000080 R09: ffff8d8e0b15b980
<br>[ +0.000003] R10: 00000000000380e0 R11: 0000000000000000 R12: 0000000000000080
<br>[ +0.000002] R13: 0000000000000002 R14: ffff9c4f89c0fb0e R15: ffff9c4f89c0fb0f
<br>[ +0.000004] FS: 00007f9ad2176c40(0000) GS:ffff8d90fe9c0000(0000) knlGS:0000000000000000
<br>[ +0.000003] CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033
<br>[ +0.000004] CR2: 00000000000004c0 CR3: 0000000121bc4000 CR4: 0000000000750ee0
<br>[ +0.000003] PKRU: 55555554
<br>[ +0.000003] Call Trace:
<br>[ +0.000006] &lt;TASK&gt;
<br>[ +0.000006] ? __die+0x23/0x70
<br>[ +0.000011] ? page_fault_oops+0x17d/0x4c0
<br>[ +0.000008] ? preempt_count_add+0x6e/0xa0
<br>[ +0.000008] ? srso_alias_return_thunk+0x5/0x7f
<br>[ +0.000011] ? exc_page_fault+0x7f/0x180
<br>[ +0.000009] ? asm_exc_page_fault+0x26/0x30
<br>[ +0.000013] ? i2c_transfer+0xd/0x100
<br>[ +0.000010] drm_do_probe_ddc_edid+0xc2/0x140 [drm]
<br>[ +0.000067] ? srso_alias_return_thunk+0x5/0x7f
<br>[ +0.000006] ? <em>drm</em>do_get_edid+0x97/0x3c0 [drm]
<br>[ +0.000043] ? __pfx_drm_do_probe_ddc_edid+0x10/0x10 [drm]
<br>[ +0.000042] edid_block_read+0x3b/0xd0 [drm]
<br>[ +0.000043] <em>drm</em>do_get_edid+0xb6/0x3c0 [drm]
<br>[ +0.000041] ? __pfx_drm_do_probe_ddc_edid+0x10/0x10 [drm]
<br>[ +0.000043] drm_edid_read_custom+0x37/0xd0 [drm]
<br>[ +0.000044] amdgpu_dm_connector_mode_valid+0x129/0x1d0 [amdgpu]
<br>[ +0.000153] drm_connector_mode_valid+0x3b/0x60 [drm_kms_helper]
<br>[ +0.000000] __drm_helper_update_and_validate+0xfe/0x3c0 [drm_kms_helper]
<br>[ +0.000000] ? amdgpu_dm_connector_get_modes+0xb6/0x520 [amdgpu]
<br>[ +0.000000] ? srso_alias_return_thunk+0x5/0x7f
<br>[ +0.000000] drm_helper_probe_single_connector_modes+0x2ab/0x540 [drm_kms_helper]
<br>[ +0.000000] status_store+0xb2/0x1f0 [drm]
<br>[ +0.000000] kernfs_fop_write_iter+0x136/0x1d0
<br>[ +0.000000] vfs_write+0x24d/0x440
<br>[ +0.000000] ksys_write+0x6f/0xf0
<br>[ +0.000000] do_syscall_64+0x60/0xc0
<br>[ +0.000000] ? srso_alias_return_thunk+0x5/0x7f
<br>[ +0.000000] ? syscall_exit_to_user_mode+0x2b/0x40
<br>[ +0.000000] ? srso_alias_return_thunk+0x5/0x7f
<br>[ +0.000000] ? do_syscall_64+0x6c/0xc0
<br>[ +0.000000] ? do_syscall_64+0x6c/0xc0
<br>[ +0.000000] entry_SYSCALL_64_after_hwframe+0x6e/0xd8
<br>[ +0.000000] RIP: 0033:0x7f9ad46b4b00
<br>[ +0.000000] Code: 40 00 48 8b 15 19 b3 0d 00 f7 d8 64 89 02 48 c7 c0
ff ff ff ff eb b7 0f 1f 00 80 3d e1 3a 0e 00 00 74 17 b8 01 00 00 00 0f
05 &lt;48&gt; 3d 00 f0 ff ff 77 58 c3 0f 1f 80 00 00 00 00 48 83 ec 28
48 89
<br>[ +0.000000] RSP: 002b:00007ffcbd3bd6d8 EFLAGS: 00000202 ORIG_RAX: 0000000000000001
<br>[ +0.000000] RAX: ffffffffffffffda RBX: 0000000000000000 RCX: 00007f9ad46b4b00
<br>[ +0.000000] RDX: 0000000000000002 RSI: 00007f9ad48a7417 RDI: 0000000000000009
<br>[ +0.000000] RBP: 0000000000000002 R08
<br>---truncated---</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26728</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26701</p>
</td>
<td rowspan="1" colspan="1">
<p>Rejected reason: This CVE ID has been rejected or withdrawn by its CVE
Numbering Authority.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26701</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-1180</p>
</td>
<td rowspan="1" colspan="1">
<p>TP-Link Omada ER605 Access Control Command Injection Remote Code Execution
Vulnerability. This vulnerability allows network-adjacent attackers to
execute arbitrary code on affected installations of TP-Link Omada ER605.
Authentication is required to exploit this vulnerability.
<br>
<br>The specific issue exists within the handling of the name field in the
access control user interface. The issue results from the lack of proper
validation of a user-supplied string before using it to execute a system
call. An attacker can leverage this vulnerability to execute code in the
context of root. Was ZDI-CAN-22227.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-1180</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52641</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>fs/ntfs3: Add NULL ptr dereference checking at the end of attr_allocate_frame()
<br>
<br>It is preferable to exit through the out: label because
<br>internal debugging functions are located there.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52641</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52640</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>fs/ntfs3: Fix oob in ntfs_listxattr
<br>
<br>The length of name cannot exceed the space occupied by ea.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52640</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-45552</p>
</td>
<td rowspan="1" colspan="1">
<p>In VeridiumID before 3.5.0, a stored cross-site scripting (XSS) vulnerability
has been discovered in the admin portal that allows an authenticated attacker
to take over all accounts by sending malicious input via the self-service
portal.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-45552</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-44040</p>
</td>
<td rowspan="1" colspan="1">
<p>In VeridiumID before 3.5.0, the identity provider page is susceptible
to a cross-site scripting (XSS) vulnerability that can be exploited by
an internal unauthenticated attacker for JavaScript execution in the context
of the user trying to authenticate.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-44040</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-44038</p>
</td>
<td rowspan="1" colspan="1">
<p>In VeridiumID before 3.5.0, the identity provider page allows an unauthenticated
attacker to discover information about registered users via an LDAP injection
attack.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-44038</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31393</p>
</td>
<td rowspan="1" colspan="1">
<p>Dragging Javascript URLs to the address bar could cause them to be loaded,
bypassing restrictions and security protections This vulnerability affects
Firefox for iOS &lt; 124.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31393</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31392</p>
</td>
<td rowspan="1" colspan="1">
<p>If an insecure element was added to a page after a delay, Firefox would
not replace the secure icon with a mixed content security status This vulnerability
affects Firefox for iOS &lt; 124.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31392</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-27673</p>
</td>
<td rowspan="1" colspan="1">
<p>Rejected reason: DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason:
This candidate was withdrawn by its CNA. Further investigation showed that
it was not a security issue. Notes: none.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-27673</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-44039</p>
</td>
<td rowspan="1" colspan="1">
<p>In VeridiumID before 3.5.0, the WebAuthn API allows an internal unauthenticated
attacker (who can pass enrollment verifications and is allowed to enroll
a FIDO key) to register their FIDO authenticator to a victim’s account
and consequently take over the account.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-44039</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28275</p>
</td>
<td rowspan="1" colspan="1">
<p>Puwell Cloud Tech Co, Ltd 360Eyes Pro v3.9.5.16(3090516) was discovered
to transmit sensitive information in cleartext. This vulnerability allows
attackers to intercept and access sensitive information, including users'
credentials and password change requests.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28275</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26727</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>btrfs: do not ASSERT() if the newly created subvolume already got read
<br>
<br>[BUG]
<br>There is a syzbot crash, triggered by the ASSERT() during subvolume
<br>creation:
<br>
<br>assertion failed: !anon_dev, in fs/btrfs/disk-io.c:1319
<br>------------[ cut here ]------------
<br>kernel BUG at fs/btrfs/disk-io.c:1319!
<br>invalid opcode: 0000 [#1] PREEMPT SMP KASAN
<br>RIP: 0010:btrfs_get_root_ref.part.0+0x9aa/0xa60
<br>&lt;TASK&gt;
<br>btrfs_get_new_fs_root+0xd3/0xf0
<br>create_subvol+0xd02/0x1650
<br>btrfs_mksubvol+0xe95/0x12b0
<br>__btrfs_ioctl_snap_create+0x2f9/0x4f0
<br>btrfs_ioctl_snap_create+0x16b/0x200
<br>btrfs_ioctl+0x35f0/0x5cf0
<br>__x64_sys_ioctl+0x19d/0x210
<br>do_syscall_64+0x3f/0xe0
<br>entry_SYSCALL_64_after_hwframe+0x63/0x6b
<br>---[ end trace 0000000000000000 ]---
<br>
<br>[CAUSE]
<br>During create_subvol(), after inserting root item for the newly created
<br>subvolume, we would trigger btrfs_get_new_fs_root() to get the
<br>btrfs_root of that subvolume.
<br>
<br>The idea here is, we have preallocated an anonymous device number for
<br>the subvolume, thus we can assign it to the new subvolume.
<br>
<br>But there is really nothing preventing things like backref walk to read
<br>the new subvolume.
<br>If that happens before we call btrfs_get_new_fs_root(), the subvolume
<br>would be read out, with a new anonymous device number assigned already.
<br>
<br>In that case, we would trigger ASSERT(), as we really expect no one to
<br>read out that subvolume (which is not yet accessible from the fs).
<br>But things like backref walk is still possible to trigger the read on
<br>the subvolume.
<br>
<br>Thus our assumption on the ASSERT() is not correct in the first place.
<br>
<br>[FIX]
<br>Fix it by removing the ASSERT(), and just free the @anon_dev, reset it
<br>to 0, and continue.
<br>
<br>If the subvolume tree is read out by something else, it should have
<br>already get a new anon_dev assigned thus we only need to free the
<br>preallocated one.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26727</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26726</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>btrfs: don't drop extent_map for free space inode on write error
<br>
<br>While running the CI for an unrelated change I hit the following panic
<br>with generic/648 on btrfs_holes_spacecache.
<br>
<br>assertion failed: block_start != EXTENT_MAP_HOLE, in fs/btrfs/extent_io.c:1385
<br>------------[ cut here ]------------
<br>kernel BUG at fs/btrfs/extent_io.c:1385!
<br>invalid opcode: 0000 [#1] PREEMPT SMP NOPTI
<br>CPU: 1 PID: 2695096 Comm: fsstress Kdump: loaded Tainted: G W 6.8.0-rc2+
#1
<br>RIP: 0010:__extent_writepage_io.constprop.0+0x4c1/0x5c0
<br>Call Trace:
<br>&lt;TASK&gt;
<br>extent_write_cache_pages+0x2ac/0x8f0
<br>extent_writepages+0x87/0x110
<br>do_writepages+0xd5/0x1f0
<br>filemap_fdatawrite_wbc+0x63/0x90
<br>__filemap_fdatawrite_range+0x5c/0x80
<br>btrfs_fdatawrite_range+0x1f/0x50
<br>btrfs_write_out_cache+0x507/0x560
<br>btrfs_write_dirty_block_groups+0x32a/0x420
<br>commit_cowonly_roots+0x21b/0x290
<br>btrfs_commit_transaction+0x813/0x1360
<br>btrfs_sync_file+0x51a/0x640
<br>__x64_sys_fdatasync+0x52/0x90
<br>do_syscall_64+0x9c/0x190
<br>entry_SYSCALL_64_after_hwframe+0x6e/0x76
<br>
<br>This happens because we fail to write out the free space cache in one
<br>instance, come back around and attempt to write it again. However on
<br>the second pass through we go to call btrfs_get_extent() on the inode
to
<br>get the extent mapping. Because this is a new block group, and with the
<br>free space inode we always search the commit root to avoid deadlocking
<br>with the tree, we find nothing and return a EXTENT_MAP_HOLE for the
<br>requested range.
<br>
<br>This happens because the first time we try to write the space cache out
<br>we hit an error, and on an error we drop the extent mapping. This is
<br>normal for normal files, but the free space cache inode is special. We
<br>always expect the extent map to be correct. Thus the second time
<br>through we end up with a bogus extent map.
<br>
<br>Since we're deprecating this feature, the most straightforward way to
<br>fix this is to simply skip dropping the extent map range for this failed
<br>range.
<br>
<br>I shortened the test by using error injection to stress the area to make
<br>it easier to reproduce. With this patch in place we no longer panic
<br>with my error injection test.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26726</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26725</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>dpll: fix possible deadlock during netlink dump operation
<br>
<br>Recently, I've been hitting following deadlock warning during dpll pin
<br>dump:
<br>
<br>[52804.637962] ======================================================
<br>[52804.638536] WARNING: possible circular locking dependency detected
<br>[52804.639111] 6.8.0-rc2jiri+ #1 Not tainted
<br>[52804.639529] ------------------------------------------------------
<br>[52804.640104] python3/2984 is trying to acquire lock:
<br>[52804.640581] ffff88810e642678 (nlk_cb_mutex-GENERIC){+.+.}-{3:3}, at:
netlink_dump+0xb3/0x780
<br>[52804.641417]
<br>but task is already holding lock:
<br>[52804.642010] ffffffff83bde4c8 (dpll_lock){+.+.}-{3:3}, at: dpll_lock_dumpit+0x13/0x20
<br>[52804.642747]
<br>which lock already depends on the new lock.
<br>
<br>[52804.643551]
<br>the existing dependency chain (in reverse order) is:
<br>[52804.644259]
<br>-&gt; #1 (dpll_lock){+.+.}-{3:3}:
<br>[52804.644836] lock_acquire+0x174/0x3e0
<br>[52804.645271] __mutex_lock+0x119/0x1150
<br>[52804.645723] dpll_lock_dumpit+0x13/0x20
<br>[52804.646169] genl_start+0x266/0x320
<br>[52804.646578] __netlink_dump_start+0x321/0x450
<br>[52804.647056] genl_family_rcv_msg_dumpit+0x155/0x1e0
<br>[52804.647575] genl_rcv_msg+0x1ed/0x3b0
<br>[52804.648001] netlink_rcv_skb+0xdc/0x210
<br>[52804.648440] genl_rcv+0x24/0x40
<br>[52804.648831] netlink_unicast+0x2f1/0x490
<br>[52804.649290] netlink_sendmsg+0x36d/0x660
<br>[52804.649742] __sock_sendmsg+0x73/0xc0
<br>[52804.650165] __sys_sendto+0x184/0x210
<br>[52804.650597] __x64_sys_sendto+0x72/0x80
<br>[52804.651045] do_syscall_64+0x6f/0x140
<br>[52804.651474] entry_SYSCALL_64_after_hwframe+0x46/0x4e
<br>[52804.652001]
<br>-&gt; #0 (nlk_cb_mutex-GENERIC){+.+.}-{3:3}:
<br>[52804.652650] check_prev_add+0x1ae/0x1280
<br>[52804.653107] __lock_acquire+0x1ed3/0x29a0
<br>[52804.653559] lock_acquire+0x174/0x3e0
<br>[52804.653984] __mutex_lock+0x119/0x1150
<br>[52804.654423] netlink_dump+0xb3/0x780
<br>[52804.654845] __netlink_dump_start+0x389/0x450
<br>[52804.655321] genl_family_rcv_msg_dumpit+0x155/0x1e0
<br>[52804.655842] genl_rcv_msg+0x1ed/0x3b0
<br>[52804.656272] netlink_rcv_skb+0xdc/0x210
<br>[52804.656721] genl_rcv+0x24/0x40
<br>[52804.657119] netlink_unicast+0x2f1/0x490
<br>[52804.657570] netlink_sendmsg+0x36d/0x660
<br>[52804.658022] __sock_sendmsg+0x73/0xc0
<br>[52804.658450] __sys_sendto+0x184/0x210
<br>[52804.658877] __x64_sys_sendto+0x72/0x80
<br>[52804.659322] do_syscall_64+0x6f/0x140
<br>[52804.659752] entry_SYSCALL_64_after_hwframe+0x46/0x4e
<br>[52804.660281]
<br>other info that might help us debug this:
<br>
<br>[52804.661077] Possible unsafe locking scenario:
<br>
<br>[52804.661671] CPU0 CPU1
<br>[52804.662129] ---- ----
<br>[52804.662577] lock(dpll_lock);
<br>[52804.662924] lock(nlk_cb_mutex-GENERIC);
<br>[52804.663538] lock(dpll_lock);
<br>[52804.664073] lock(nlk_cb_mutex-GENERIC);
<br>[52804.664490]
<br>
<br>The issue as follows: __netlink_dump_start() calls control-&gt;start(cb)
<br>with nlk-&gt;cb_mutex held. In control-&gt;start(cb) the dpll_lock is
taken.
<br>Then nlk-&gt;cb_mutex is released and taken again in netlink_dump(), while
<br>dpll_lock still being held. That leads to ABBA deadlock when another
<br>CPU races with the same operation.
<br>
<br>Fix this by moving dpll_lock taking into dumpit() callback which ensures
<br>correct lock taking order.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26725</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26724</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>net/mlx5: DPLL, Fix possible use after free after delayed work timer triggers
<br>
<br>I managed to hit following use after free warning recently:
<br>
<br>[ 2169.711665] ==================================================================
<br>[ 2169.714009] BUG: KASAN: slab-use-after-free in __run_timers.part.0+0x179/0x4c0
<br>[ 2169.716293] Write of size 8 at addr ffff88812b326a70 by task swapper/4/0
<br>
<br>[ 2169.719022] CPU: 4 PID: 0 Comm: swapper/4 Not tainted 6.8.0-rc2jiri+
#2
<br>[ 2169.720974] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS
<a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org</a>04/01/2014
<br>[ 2169.722457] Call Trace:
<br>[ 2169.722756] &lt;IRQ&gt;
<br>[ 2169.723024] dump_stack_lvl+0x58/0xb0
<br>[ 2169.723417] print_report+0xc5/0x630
<br>[ 2169.723807] ? __virt_addr_valid+0x126/0x2b0
<br>[ 2169.724268] kasan_report+0xbe/0xf0
<br>[ 2169.724667] ? __run_timers.part.0+0x179/0x4c0
<br>[ 2169.725116] ? __run_timers.part.0+0x179/0x4c0
<br>[ 2169.725570] __run_timers.part.0+0x179/0x4c0
<br>[ 2169.726003] ? call_timer_fn+0x320/0x320
<br>[ 2169.726404] ? lock_downgrade+0x3a0/0x3a0
<br>[ 2169.726820] ? kvm_clock_get_cycles+0x14/0x20
<br>[ 2169.727257] ? ktime_get+0x92/0x150
<br>[ 2169.727630] ? lapic_next_deadline+0x35/0x60
<br>[ 2169.728069] run_timer_softirq+0x40/0x80
<br>[ 2169.728475] __do_softirq+0x1a1/0x509
<br>[ 2169.728866] irq_exit_rcu+0x95/0xc0
<br>[ 2169.729241] sysvec_apic_timer_interrupt+0x6b/0x80
<br>[ 2169.729718] &lt;/IRQ&gt;
<br>[ 2169.729993] &lt;TASK&gt;
<br>[ 2169.730259] asm_sysvec_apic_timer_interrupt+0x16/0x20
<br>[ 2169.730755] RIP: 0010:default_idle+0x13/0x20
<br>[ 2169.731190] Code: c0 08 00 00 00 4d 29 c8 4c 01 c7 4c 29 c2 e9 72 ff
ff ff cc cc cc cc 8b 05 9a 7f 1f 02 85 c0 7e 07 0f 00 2d cf 69 43 00 fb
f4 &lt;fa&gt; c3 66 66 2e 0f 1f 84 00 00 00 00 00 65 48 8b 04 25 c0 93
04 00
<br>[ 2169.732759] RSP: 0018:ffff888100dbfe10 EFLAGS: 00000242
<br>[ 2169.733264] RAX: 0000000000000001 RBX: ffff888100d9c200 RCX: ffffffff8241bd62
<br>[ 2169.733925] RDX: ffffed109a848b15 RSI: 0000000000000004 RDI: ffffffff8127ac55
<br>[ 2169.734566] RBP: 0000000000000004 R08: 0000000000000000 R09: ffffed109a848b14
<br>[ 2169.735200] R10: ffff8884d42458a3 R11: 000000000000ba7e R12: ffffffff83d7d3a0
<br>[ 2169.735835] R13: 1ffff110201b7fc6 R14: 0000000000000000 R15: ffff888100d9c200
<br>[ 2169.736478] ? ct_kernel_exit.constprop.0+0xa2/0xc0
<br>[ 2169.736954] ? do_idle+0x285/0x290
<br>[ 2169.737323] default_idle_call+0x63/0x90
<br>[ 2169.737730] do_idle+0x285/0x290
<br>[ 2169.738089] ? arch_cpu_idle_exit+0x30/0x30
<br>[ 2169.738511] ? mark_held_locks+0x1a/0x80
<br>[ 2169.738917] ? lockdep_hardirqs_on_prepare+0x12e/0x200
<br>[ 2169.739417] cpu_startup_entry+0x30/0x40
<br>[ 2169.739825] start_secondary+0x19a/0x1c0
<br>[ 2169.740229] ? set_cpu_sibling_map+0xbd0/0xbd0
<br>[ 2169.740673] secondary_startup_64_no_verify+0x15d/0x16b
<br>[ 2169.741179] &lt;/TASK&gt;
<br>
<br>[ 2169.741686] Allocated by task 1098:
<br>[ 2169.742058] kasan_save_stack+0x1c/0x40
<br>[ 2169.742456] kasan_save_track+0x10/0x30
<br>[ 2169.742852] __kasan_kmalloc+0x83/0x90
<br>[ 2169.743246] mlx5_dpll_probe+0xf5/0x3c0 [mlx5_dpll]
<br>[ 2169.743730] auxiliary_bus_probe+0x62/0xb0
<br>[ 2169.744148] really_probe+0x127/0x590
<br>[ 2169.744534] __driver_probe_device+0xd2/0x200
<br>[ 2169.744973] device_driver_attach+0x6b/0xf0
<br>[ 2169.745402] bind_store+0x90/0xe0
<br>[ 2169.745761] kernfs_fop_write_iter+0x1df/0x2a0
<br>[ 2169.746210] vfs_write+0x41f/0x790
<br>[ 2169.746579] ksys_write+0xc7/0x160
<br>[ 2169.746947] do_syscall_64+0x6f/0x140
<br>[ 2169.747333] entry_SYSCALL_64_after_hwframe+0x46/0x4e
<br>
<br>[ 2169.748049] Freed by task 1220:
<br>[ 2169.748393] kasan_save_stack+0x1c/0x40
<br>[ 2169.748789] kasan_save_track+0x10/0x30
<br>[ 2169.749188] kasan_save_free_info+0x3b/0x50
<br>[ 2169.749621] poison_slab_object+0x106/0x180
<br>[ 2169.750044] __kasan_slab_free+0x14/0x50
<br>[ 2169.750451] kfree+0x118/0x330
<br>[ 2169.750792] mlx5_dpll_remove+0xf5/0x110 [mlx5_dpll]
<br>[ 2169.751271] auxiliary_bus_remove+0x2e/0x40
<br>[ 2169.751694] device_release_driver_internal+0x24b/0x2e0
<br>[ 2169.752191] unbind_store+0xa6/0xb0
<br>[ 2169.752563] kernfs_fo
<br>---truncated---</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26724</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26723</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>lan966x: Fix crash when adding interface under a lag
<br>
<br>There is a crash when adding one of the lan966x interfaces under a lag
<br>interface. The issue can be reproduced like this:
<br>ip link add name bond0 type bond miimon 100 mode balance-xor
<br>ip link set dev eth0 master bond0
<br>
<br>The reason is because when adding a interface under the lag it would go
<br>through all the ports and try to figure out which other ports are under
<br>that lag interface. And the issue is that lan966x can have ports that
are
<br>NULL pointer as they are not probed. So then iterating over these ports
<br>it would just crash as they are NULL pointers.
<br>The fix consists in actually checking for NULL pointers before accessing
<br>something from the ports. Like we do in other places.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26723</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26722</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>ASoC: rt5645: Fix deadlock in rt5645_jack_detect_work()
<br>
<br>There is a path in rt5645_jack_detect_work(), where rt5645-&gt;jd_mutex
<br>is left locked forever. That may lead to deadlock
<br>when rt5645_jack_detect_work() is called for the second time.
<br>
<br>Found by Linux Verification Center (<a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">linuxtesting.org</a>) with SVACE.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26722</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26721</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>drm/i915/dsc: Fix the macro that calculates DSCC_/DSCA_ PPS reg address
<br>
<br>Commit bd077259d0a9 ("drm/i915/vdsc: Add function to read any PPS
<br>register") defines a new macro to calculate the DSC PPS register
<br>addresses with PPS number as an input. This macro correctly calculates
<br>the addresses till PPS 11 since the addresses increment by 4. So in that
<br>case the following macro works correctly to give correct register
<br>address:
<br>
<br>_MMIO(_DSCA_PPS_0 + (pps) * 4)
<br>
<br>However after PPS 11, the register address for PPS 12 increments by 12
<br>because of RC Buffer memory allocation in between. Because of this
<br>discontinuity in the address space, the macro calculates wrong addresses
<br>for PPS 12 - 16 resulting into incorrect DSC PPS parameter value
<br>read/writes causing DSC corruption.
<br>
<br>This fixes it by correcting this macro to add the offset of 12 for PPS
<br>&gt;=12.
<br>
<br>v3: Add correct paranthesis for pps argument (Jani Nikula)
<br>
<br>(cherry picked from commit 6074be620c31dc2ae11af96a1a5ea95580976fb5)</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26721</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26720</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>mm/writeback: fix possible divide-by-zero in wb_dirty_limits(), again
<br>
<br>(struct dirty_throttle_control <em>)-&gt;thresh is an unsigned long, but is<br>passed as the u32 divisor argument to div_u64(). On architectures where<br>unsigned long is 64 bytes, the argument will be implicitly truncated.<br><br>Use div64_u64() instead of div_u64() so that the value used in the "is<br>this a safe division" check is the same as the divisor.<br><br>Also, remove redundant cast of the numerator to u64, as that should happen<br>implicitly.<br><br>This would be difficult to exploit in memcg domain, given the ratio-based<br>arithmetic domain_drity_limits() uses, but is much easier in global<br>writeback domain with a BDI_CAP_STRICTLIMIT-backing device, using e.g.<br>vm.dirty_bytes=(1&lt;&lt;32)</em>PAGE_SIZE
so that dtc-&gt;thresh == (1&lt;&lt;32)</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26720</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26719</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>nouveau: offload fence uevents work to workqueue
<br>
<br>This should break the deadlock between the fctx lock and the irq lock.
<br>
<br>This offloads the processing off the work from the irq into a workqueue.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26719</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26718</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>dm-crypt, dm-verity: disable tasklets
<br>
<br>Tasklets have an inherent problem with memory corruption. The function
<br>tasklet_action_common calls tasklet_trylock, then it calls the tasklet
<br>callback and then it calls tasklet_unlock. If the tasklet callback frees
<br>the structure that contains the tasklet or if it calls some code that
may
<br>free it, tasklet_unlock will write into free memory.
<br>
<br>The commits 8e14f610159d and d9a02e016aaf try to fix it for dm-crypt,
but
<br>it is not a sufficient fix and the data corruption can still happen [1].
<br>There is no fix for dm-verity and dm-verity will write into free memory
<br>with every tasklet-processed bio.
<br>
<br>There will be atomic workqueues implemented in the kernel 6.9 [2]. They
<br>will have better interface and they will not suffer from the memory
<br>corruption problem.
<br>
<br>But we need something that stops the memory corruption now and that can
be
<br>backported to the stable kernels. So, I'm proposing this commit that
<br>disables tasklets in both dm-crypt and dm-verity. This commit doesn't
<br>remove the tasklet support, because the tasklet code will be reused when
<br>atomic workqueues will be implemented.
<br>
<br>[1] <a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://lore.kernel.org/all/d390d7ee-f142-44d3-822a-87949e14608b@suse.de/T/<br>[2]</a> 
<a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://lore.kernel.org/lkml/20240130091300.2968534-1-tj@kernel.org/</a>
</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26718</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26717</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>HID: i2c-hid-of: fix NULL-deref on failed power up
<br>
<br>A while back the I2C HID implementation was split in an ACPI and OF
<br>part, but the new OF driver never initialises the client pointer which
<br>is dereferenced on power-up failures.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26717</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26716</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>usb: core: Prevent null pointer dereference in update_port_device_state
<br>
<br>Currently, the function update_port_device_state gets the usb_hub from
<br>udev-&gt;parent by calling usb_hub_to_struct_hub.
<br>However, in case the actconfig or the maxchild is 0, the usb_hub would
<br>be NULL and upon further accessing to get port_dev would result in null
<br>pointer dereference.
<br>
<br>Fix this by introducing an if check after the usb_hub is populated.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26716</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26715</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>usb: dwc3: gadget: Fix NULL pointer dereference in dwc3_gadget_suspend
<br>
<br>In current scenario if Plug-out and Plug-In performed continuously
<br>there could be a chance while checking for dwc-&gt;gadget_driver in
<br>dwc3_gadget_suspend, a NULL pointer dereference may occur.
<br>
<br>Call Stack:
<br>
<br>\tCPU1: CPU2:
<br>\tgadget_unbind_driver dwc3_suspend_common
<br>\tdwc3_gadget_stop dwc3_gadget_suspend
<br>dwc3_disconnect_gadget
<br>
<br>CPU1 basically clears the variable and CPU2 checks the variable.
<br>Consider CPU1 is running and right before gadget_driver is cleared
<br>and in parallel CPU2 executes dwc3_gadget_suspend where it finds
<br>dwc-&gt;gadget_driver which is not NULL and resumes execution and then
<br>CPU1 completes execution. CPU2 executes dwc3_disconnect_gadget where
<br>it checks dwc-&gt;gadget_driver is already NULL because of which the
<br>NULL pointer deference occur.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26715</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26714</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>interconnect: qcom: sc8180x: Mark CO0 BCM keepalive
<br>
<br>The CO0 BCM needs to be up at all times, otherwise some hardware (like
<br>the UFS controller) loses its connection to the rest of the SoC,
<br>resulting in a hang of the platform, accompanied by a spectacular
<br>logspam.
<br>
<br>Mark it as keepalive to prevent such cases.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26714</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26713</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>powerpc/pseries/iommu: Fix iommu initialisation during DLPAR add
<br>
<br>When a PCI device is dynamically added, the kernel oopses with a NULL
<br>pointer dereference:
<br>
<br>BUG: Kernel NULL pointer dereference on read at 0x00000030
<br>Faulting instruction address: 0xc0000000006bbe5c
<br>Oops: Kernel access of bad area, sig: 11 [#1]
<br>LE PAGE_SIZE=64K MMU=Radix SMP NR_CPUS=2048 NUMA pSeries
<br>Modules linked in: rpadlpar_io rpaphp rpcsec_gss_krb5 auth_rpcgss nfsv4
dns_resolver nfs lockd grace fscache netfs xsk_diag bonding nft_compat
nf_tables nfnetlink rfkill binfmt_misc dm_multipath rpcrdma sunrpc rdma_ucm
ib_srpt ib_isert iscsi_target_mod target_core_mod ib_umad ib_iser libiscsi
scsi_transport_iscsi ib_ipoib rdma_cm iw_cm ib_cm mlx5_ib ib_uverbs ib_core
pseries_rng drm drm_panel_orientation_quirks xfs libcrc32c mlx5_core mlxfw
sd_mod t10_pi sg tls ibmvscsi ibmveth scsi_transport_srp vmx_crypto pseries_wdt
psample dm_mirror dm_region_hash dm_log dm_mod fuse
<br>CPU: 17 PID: 2685 Comm: drmgr Not tainted 6.7.0-203405+ #66
<br>Hardware name: IBM,9080-HEX POWER10 (raw) 0x800200 0xf000006 of:IBM,FW1060.00
(NH1060_008) hv:phyp pSeries
<br>NIP: c0000000006bbe5c LR: c000000000a13e68 CTR: c0000000000579f8
<br>REGS: c00000009924f240 TRAP: 0300 Not tainted (6.7.0-203405+)
<br>MSR: 8000000000009033 &lt;SF,EE,ME,IR,DR,RI,LE&gt; CR: 24002220 XER: 20040006
<br>CFAR: c000000000a13e64 DAR: 0000000000000030 DSISR: 40000000 IRQMASK:
0
<br>...
<br>NIP sysfs_add_link_to_group+0x34/0x94
<br>LR iommu_device_link+0x5c/0x118
<br>Call Trace:
<br>iommu_init_device+0x26c/0x318 (unreliable)
<br>iommu_device_link+0x5c/0x118
<br>iommu_init_device+0xa8/0x318
<br>iommu_probe_device+0xc0/0x134
<br>iommu_bus_notifier+0x44/0x104
<br>notifier_call_chain+0xb8/0x19c
<br>blocking_notifier_call_chain+0x64/0x98
<br>bus_notify+0x50/0x7c
<br>device_add+0x640/0x918
<br>pci_device_add+0x23c/0x298
<br>of_create_pci_dev+0x400/0x884
<br>of_scan_pci_dev+0x124/0x1b0
<br>__of_scan_bus+0x78/0x18c
<br>pcibios_scan_phb+0x2a4/0x3b0
<br>init_phb_dynamic+0xb8/0x110
<br>dlpar_add_slot+0x170/0x3b8 [rpadlpar_io]
<br>add_slot_store.part.0+0xb4/0x130 [rpadlpar_io]
<br>kobj_attr_store+0x2c/0x48
<br>sysfs_kf_write+0x64/0x78
<br>kernfs_fop_write_iter+0x1b0/0x290
<br>vfs_write+0x350/0x4a0
<br>ksys_write+0x84/0x140
<br>system_call_exception+0x124/0x330
<br>system_call_vectored_common+0x15c/0x2ec
<br>
<br>Commit a940904443e4 ("powerpc/iommu: Add iommu_ops to report capabilities
<br>and allow blocking domains") broke DLPAR add of PCI devices.
<br>
<br>The above added iommu_device structure to pci_controller. During
<br>system boot, PCI devices are discovered and this newly added iommu_device
<br>structure is initialized by a call to iommu_device_register().
<br>
<br>During DLPAR add of a PCI device, a new pci_controller structure is
<br>allocated but there are no calls made to iommu_device_register()
<br>interface.
<br>
<br>Fix is to register the iommu device during DLPAR add as well.
<br>
<br>[mpe: Trim oops and tweak some change log wording]</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26713</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26712</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>powerpc/kasan: Fix addr error caused by page alignment
<br>
<br>In kasan_init_region, when k_start is not page aligned, at the begin of
<br>for loop, k_cur = k_start &amp; PAGE_MASK is less than k_start, and then
<br>`va = block + k_cur - k_start` is less than block, the addr va is invalid,
<br>because the memory address space from va to block is not alloced by
<br>memblock_alloc, which will not be reserved by memblock_reserve later,
it
<br>will be used by other places.
<br>
<br>As a result, memory overwriting occurs.
<br>
<br>for example:
<br>int <strong>init </strong>weak kasan_init_region(void <em>start, size_t size)<br>{<br>[...]<br>\t/</em> if
say block(dcd97000) k_start(feef7400) k_end(feeff3fe) <em>/<br>\tblock = memblock_alloc(k_end - k_start, PAGE_SIZE);<br>\t[...]<br>\tfor (k_cur = k_start &amp; PAGE_MASK; k_cur &lt; k_end; k_cur += PAGE_SIZE) {<br>\t\t/</em> at
the begin of for loop
<br>\t\t <em> block(dcd97000) va(dcd96c00) k_cur(feef7000) k_start(feef7400)<br>\t\t </em> va(dcd96c00)
is less than block(dcd97000), va is invalid
<br>\t\t <em>/<br>\t\tvoid </em>va = block + k_cur - k_start;
<br>\t\t[...]
<br>\t}
<br>[...]
<br>}
<br>
<br>Therefore, page alignment is performed on k_start before
<br>memblock_alloc() to ensure the validity of the VA address.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26712</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26711</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>iio: adc: ad4130: zero-initialize clock init data
<br>
<br>The clk_init_data struct does not have all its members
<br>initialized, causing issues when trying to expose the internal
<br>clock on the CLK pin.
<br>
<br>Fix this by zero-initializing the clk_init_data struct.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26711</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26710</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>powerpc/kasan: Limit KASAN thread size increase to 32KB
<br>
<br>KASAN is seen to increase stack usage, to the point that it was reported
<br>to lead to stack overflow on some 32-bit machines (see link).
<br>
<br>To avoid overflows the stack size was doubled for KASAN builds in
<br>commit 3e8635fb2e07 ("powerpc/kasan: Force thread size increase with
<br>KASAN").
<br>
<br>However with a 32KB stack size to begin with, the doubling leads to a
<br>64KB stack, which causes build errors:
<br>arch/powerpc/kernel/switch.S:249: Error: operand out of range (0x000000000000fe50
is not between 0xffffffffffff8000 and 0x0000000000007fff)
<br>
<br>Although the asm could be reworked, in practice a 32KB stack seems
<br>sufficient even for KASAN builds - the additional usage seems to be in
<br>the 2-3KB range for a 64-bit KASAN build.
<br>
<br>So only increase the stack for KASAN if the stack size is &lt; 32KB.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26710</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26709</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>powerpc/iommu: Fix the missing iommu_group_put() during platform domain
attach
<br>
<br>The function spapr_tce_platform_iommu_attach_dev() is missing to call
<br>iommu_group_put() when the domain is already set. This refcount leak
<br>shows up with BUG_ON() during DLPAR remove operation as:
<br>
<br>KernelBug: Kernel bug in state 'None': kernel BUG at arch/powerpc/platforms/pseries/iommu.c:100!
<br>Oops: Exception in kernel mode, sig: 5 [#1]
<br>LE PAGE_SIZE=64K MMU=Radix SMP NR_CPUS=8192 NUMA pSeries
<br>&lt;snip&gt;
<br>Hardware name: IBM,9080-HEX POWER10 (raw) 0x800200 0xf000006 of:IBM,FW1060.00
(NH1060_016) hv:phyp pSeries
<br>NIP: c0000000000ff4d4 LR: c0000000000ff4cc CTR: 0000000000000000
<br>REGS: c0000013aed5f840 TRAP: 0700 Tainted: G I (6.8.0-rc3-autotest-g99bd3cb0d12e)
<br>MSR: 8000000000029033 &lt;SF,EE,ME,IR,DR,RI,LE&gt; CR: 44002402 XER: 20040000
<br>CFAR: c000000000a0d170 IRQMASK: 0
<br>...
<br>NIP iommu_reconfig_notifier+0x94/0x200
<br>LR iommu_reconfig_notifier+0x8c/0x200
<br>Call Trace:
<br>iommu_reconfig_notifier+0x8c/0x200 (unreliable)
<br>notifier_call_chain+0xb8/0x19c
<br>blocking_notifier_call_chain+0x64/0x98
<br>of_reconfig_notify+0x44/0xdc
<br>of_detach_node+0x78/0xb0
<br>ofdt_write.part.0+0x86c/0xbb8
<br>proc_reg_write+0xf4/0x150
<br>vfs_write+0xf8/0x488
<br>ksys_write+0x84/0x140
<br>system_call_exception+0x138/0x330
<br>system_call_vectored_common+0x15c/0x2ec
<br>
<br>The patch adds the missing iommu_group_put() call.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26709</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26708</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>mptcp: really cope with fastopen race
<br>
<br>Fastopen and PM-trigger subflow shutdown can race, as reported by
<br>syzkaller.
<br>
<br>In my first attempt to close such race, I missed the fact that
<br>the subflow status can change again before the subflow_state_change
<br>callback is invoked.
<br>
<br>Address the issue additionally copying with all the states directly
<br>reachable from TCP_FIN_WAIT1.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26708</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26707</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>net: hsr: remove WARN_ONCE() in send_hsr_supervision_frame()
<br>
<br>Syzkaller reported [1] hitting a warning after failing to allocate
<br>resources for skb in hsr_init_skb(). Since a WARN_ONCE() call will
<br>not help much in this case, it might be prudent to switch to
<br>netdev_warn_once(). At the very least it will suppress syzkaller
<br>reports such as [1].
<br>
<br>Just in case, use netdev_warn_once() in send_prp_supervision_frame()
<br>for similar reasons.
<br>
<br>[1]
<br>HSR: Could not send supervision frame
<br>WARNING: CPU: 1 PID: 85 at net/hsr/hsr_device.c:294 send_hsr_supervision_frame+0x60a/0x810
net/hsr/hsr_device.c:294
<br>RIP: 0010:send_hsr_supervision_frame+0x60a/0x810 net/hsr/hsr_device.c:294
<br>...
<br>Call Trace:
<br>&lt;IRQ&gt;
<br>hsr_announce+0x114/0x370 net/hsr/hsr_device.c:382
<br>call_timer_fn+0x193/0x590 kernel/time/timer.c:1700
<br>expire_timers kernel/time/timer.c:1751 [inline]
<br>__run_timers+0x764/0xb20 kernel/time/timer.c:2022
<br>run_timer_softirq+0x58/0xd0 kernel/time/timer.c:2035
<br>__do_softirq+0x21a/0x8de kernel/softirq.c:553
<br>invoke_softirq kernel/softirq.c:427 [inline]
<br>__irq_exit_rcu kernel/softirq.c:632 [inline]
<br>irq_exit_rcu+0xb7/0x120 kernel/softirq.c:644
<br>sysvec_apic_timer_interrupt+0x95/0xb0 arch/x86/kernel/apic/apic.c:1076
<br>&lt;/IRQ&gt;
<br>&lt;TASK&gt;
<br>asm_sysvec_apic_timer_interrupt+0x1a/0x20 arch/x86/include/asm/idtentry.h:649
<br>...
<br>
<br>This issue is also found in older kernels (at least up to 5.10).</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26707</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26706</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>parisc: Fix random data corruption from exception handler
<br>
<br>The current exception handler implementation, which assists when accessing
<br>user space memory, may exhibit random data corruption if the compiler
decides
<br>to use a different register than the specified register %r29 (defined
in
<br>ASM_EXCEPTIONTABLE_REG) for the error code. If the compiler choose another
<br>register, the fault handler will nevertheless store -EFAULT into %r29
and thus
<br>trash whatever this register is used for.
<br>Looking at the assembly I found that this happens sometimes in emulate_ldd().
<br>
<br>To solve the issue, the easiest solution would be if it somehow is
<br>possible to tell the fault handler which register is used to hold the
error
<br>code. Using %0 or %1 in the inline assembly is not posssible as it will
show
<br>up as e.g. %r29 (with the "%r" prefix), which the GNU assembler can not
<br>convert to an integer.
<br>
<br>This patch takes another, better and more flexible approach:
<br>We extend the __ex_table (which is out of the execution path) by one 32-word.
<br>In this word we tell the compiler to insert the assembler instruction
<br>"or %r0,%r0,%reg", where %reg references the register which the compiler
<br>choosed for the error return code.
<br>In case of an access failure, the fault handler finds the __ex_table entry
and
<br>can examine the opcode. The used register is encoded in the lowest 5 bits,
and
<br>the fault handler can then store -EFAULT into this register.
<br>
<br>Since we extend the __ex_table to 3 words we can't use the BUILDTIME_TABLE_SORT
<br>config option any longer.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26706</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26705</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>parisc: BTLB: Fix crash when setting up BTLB at CPU bringup
<br>
<br>When using hotplug and bringing up a 32-bit CPU, ask the firmware about
the
<br>BTLB information to set up the static (block) TLB entries.
<br>
<br>For that write access to the static btlb_info struct is needed, but
<br>since it is marked __ro_after_init the kernel segfaults with missing
<br>write permissions.
<br>
<br>Fix the crash by dropping the __ro_after_init annotation.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26705</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26704</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>ext4: fix double-free of blocks due to wrong extents moved_len
<br>
<br>In ext4_move_extents(), moved_len is only updated when all moves are
<br>successfully executed, and only discards orig_inode and donor_inode
<br>preallocations when moved_len is not zero. When the loop fails to exit
<br>after successfully moving some extents, moved_len is not updated and
<br>remains at 0, so it does not discard the preallocations.
<br>
<br>If the moved extents overlap with the preallocated extents, the
<br>overlapped extents are freed twice in ext4_mb_release_inode_pa() and
<br>ext4_process_freed_data() (as described in commit 94d7c16cbbbd ("ext4:
<br>Fix double-free of blocks with EXT4_IOC_MOVE_EXT")), and bb_free is
<br>incremented twice. Hence when trim is executed, a zero-division bug is
<br>triggered in mb_update_avg_fragment_size() because bb_free is not zero
<br>and bb_fragments is zero.
<br>
<br>Therefore, update move_len after each extent move to avoid the issue.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26704</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26703</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>tracing/timerlat: Move hrtimer_init to timerlat_fd open()
<br>
<br>Currently, the timerlat's hrtimer is initialized at the first read of
<br>timerlat_fd, and destroyed at close(). It works, but it causes an error
<br>if the user program open() and close() the file without reading.
<br>
<br>Here's an example:
<br>
<br># echo NO_OSNOISE_WORKLOAD &gt; /sys/kernel/debug/tracing/osnoise/options
<br># echo timerlat &gt; /sys/kernel/debug/tracing/current_tracer
<br>
<br># cat &lt;&lt;EOF &gt; ./timerlat_<a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">load.py</a>
<br># !/usr/bin/env python3
<br>
<br>timerlat_fd = open("/sys/kernel/tracing/osnoise/per_cpu/cpu0/timerlat_fd",
'r')
<br>timerlat_fd.close();
<br>EOF
<br>
<br># ./taskset -c 0 ./timerlat_<a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">load.py</a>
<br>&lt;BOOM&gt;
<br>
<br>BUG: kernel NULL pointer dereference, address: 0000000000000010
<br>#PF: supervisor read access in kernel mode
<br>#PF: error_code(0x0000) - not-present page
<br>PGD 0 P4D 0
<br>Oops: 0000 [#1] PREEMPT SMP NOPTI
<br>CPU: 1 PID: 2673 Comm: python3 Not tainted 6.6.13-200.fc39.x86_64 #1
<br>Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-1.fc39
04/01/2014
<br>RIP: 0010:hrtimer_active+0xd/0x50
<br>Code: 2e 0f 1f 84 00 00 00 00 00 0f 1f 40 00 90 90 90 90 90 90 90 90 90
90 90 90 90 90 90 90 f3 0f 1e fa 0f 1f 44 00 00 48 8b 57 30 &lt;8b&gt;
42 10 a8 01 74 09 f3 90 8b 42 10 a8 01 75 f7 80 7f 38 00 75 1d
<br>RSP: 0018:ffffb031009b7e10 EFLAGS: 00010286
<br>RAX: 000000000002db00 RBX: ffff9118f786db08 RCX: 0000000000000000
<br>RDX: 0000000000000000 RSI: ffff9117a0e64400 RDI: ffff9118f786db08
<br>RBP: ffff9118f786db80 R08: ffff9117a0ddd420 R09: ffff9117804d4f70
<br>R10: 0000000000000000 R11: 0000000000000000 R12: ffff9118f786db08
<br>R13: ffff91178fdd5e20 R14: ffff9117840978c0 R15: 0000000000000000
<br>FS: 00007f2ffbab1740(0000) GS:ffff9118f7840000(0000) knlGS:0000000000000000
<br>CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033
<br>CR2: 0000000000000010 CR3: 00000001b402e000 CR4: 0000000000750ee0
<br>PKRU: 55555554
<br>Call Trace:
<br>&lt;TASK&gt;
<br>? __die+0x23/0x70
<br>? page_fault_oops+0x171/0x4e0
<br>? srso_alias_return_thunk+0x5/0x7f
<br>? avc_has_extended_perms+0x237/0x520
<br>? exc_page_fault+0x7f/0x180
<br>? asm_exc_page_fault+0x26/0x30
<br>? hrtimer_active+0xd/0x50
<br>hrtimer_cancel+0x15/0x40
<br>timerlat_fd_release+0x48/0xe0
<br>__fput+0xf5/0x290
<br>__x64_sys_close+0x3d/0x80
<br>do_syscall_64+0x60/0x90
<br>? srso_alias_return_thunk+0x5/0x7f
<br>? __x64_sys_ioctl+0x72/0xd0
<br>? srso_alias_return_thunk+0x5/0x7f
<br>? syscall_exit_to_user_mode+0x2b/0x40
<br>? srso_alias_return_thunk+0x5/0x7f
<br>? do_syscall_64+0x6c/0x90
<br>? srso_alias_return_thunk+0x5/0x7f
<br>? exit_to_user_mode_prepare+0x142/0x1f0
<br>? srso_alias_return_thunk+0x5/0x7f
<br>? syscall_exit_to_user_mode+0x2b/0x40
<br>? srso_alias_return_thunk+0x5/0x7f
<br>? do_syscall_64+0x6c/0x90
<br>entry_SYSCALL_64_after_hwframe+0x6e/0xd8
<br>RIP: 0033:0x7f2ffb321594
<br>Code: 00 f7 d8 64 89 01 48 83 c8 ff c3 66 2e 0f 1f 84 00 00 00 00 00 90
f3 0f 1e fa 80 3d d5 cd 0d 00 00 74 13 b8 03 00 00 00 0f 05 &lt;48&gt;
3d 00 f0 ff ff 77 3c c3 0f 1f 00 55 48 89 e5 48 83 ec 10 89 7d
<br>RSP: 002b:00007ffe8d8eef18 EFLAGS: 00000202 ORIG_RAX: 0000000000000003
<br>RAX: ffffffffffffffda RBX: 00007f2ffba4e668 RCX: 00007f2ffb321594
<br>RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000003
<br>RBP: 00007ffe8d8eef40 R08: 0000000000000000 R09: 0000000000000000
<br>R10: 55c926e3167eae79 R11: 0000000000000202 R12: 0000000000000003
<br>R13: 00007ffe8d8ef030 R14: 0000000000000000 R15: 00007f2ffba4e668
<br>&lt;/TASK&gt;
<br>CR2: 0000000000000010
<br>---[ end trace 0000000000000000 ]---
<br>
<br>Move hrtimer_init to timerlat_fd open() to avoid this problem.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26703</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26702</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>iio: magnetometer: rm3100: add boundary check for the value read from
RM3100_REG_TMRC
<br>
<br>Recently, we encounter kernel crash in function rm3100_common_probe
<br>caused by out of bound access of array rm3100_samp_rates (because of
<br>underlying hardware failures). Add boundary check to prevent out of
<br>bound access.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26702</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26700</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>drm/amd/display: Fix MST Null Ptr for RV
<br>
<br>The change try to fix below error specific to RV platform:
<br>
<br>BUG: kernel NULL pointer dereference, address: 0000000000000008
<br>PGD 0 P4D 0
<br>Oops: 0000 [#1] PREEMPT SMP NOPTI
<br>CPU: 4 PID: 917 Comm: sway Not tainted 6.3.9-arch1-1 #1 124dc55df4f5272ccb409f39ef4872fc2b3376a2
<br>Hardware name: LENOVO 20NKS01Y00/20NKS01Y00, BIOS R12ET61W(1.31 ) 07/28/2022
<br>RIP: 0010:drm_dp_atomic_find_time_slots+0x5e/0x260 [drm_display_helper]
<br>Code: 01 00 00 48 8b 85 60 05 00 00 48 63 80 88 00 00 00 3b 43 28 0f 8d
2e 01 00 00 48 8b 53 30 48 8d 04 80 48 8d 04 c2 48 8b 40 18 &lt;48&gt;
8&gt;
<br>RSP: 0018:ffff960cc2df77d8 EFLAGS: 00010293
<br>RAX: 0000000000000000 RBX: ffff8afb87e81280 RCX: 0000000000000224
<br>RDX: ffff8afb9ee37c00 RSI: ffff8afb8da1a578 RDI: ffff8afb87e81280
<br>RBP: ffff8afb83d67000 R08: 0000000000000001 R09: ffff8afb9652f850
<br>R10: ffff960cc2df7908 R11: 0000000000000002 R12: 0000000000000000
<br>R13: ffff8afb8d7688a0 R14: ffff8afb8da1a578 R15: 0000000000000224
<br>FS: 00007f4dac35ce00(0000) GS:ffff8afe30b00000(0000) knlGS:0000000000000000
<br>CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033
<br>CR2: 0000000000000008 CR3: 000000010ddc6000 CR4: 00000000003506e0
<br>Call Trace:
<br>&lt;TASK&gt;
<br>? __die+0x23/0x70
<br>? page_fault_oops+0x171/0x4e0
<br>? plist_add+0xbe/0x100
<br>? exc_page_fault+0x7c/0x180
<br>? asm_exc_page_fault+0x26/0x30
<br>? drm_dp_atomic_find_time_slots+0x5e/0x260 [drm_display_helper 0e67723696438d8e02b741593dd50d80b44c2026]
<br>? drm_dp_atomic_find_time_slots+0x28/0x260 [drm_display_helper 0e67723696438d8e02b741593dd50d80b44c2026]
<br>compute_mst_dsc_configs_for_link+0x2ff/0xa40 [amdgpu 62e600d2a75e9158e1cd0a243bdc8e6da040c054]
<br>? fill_plane_buffer_attributes+0x419/0x510 [amdgpu 62e600d2a75e9158e1cd0a243bdc8e6da040c054]
<br>compute_mst_dsc_configs_for_state+0x1e1/0x250 [amdgpu 62e600d2a75e9158e1cd0a243bdc8e6da040c054]
<br>amdgpu_dm_atomic_check+0xecd/0x1190 [amdgpu 62e600d2a75e9158e1cd0a243bdc8e6da040c054]
<br>drm_atomic_check_only+0x5c5/0xa40
<br>drm_mode_atomic_ioctl+0x76e/0xbc0
<br>? <em>copy</em>to_user+0x25/0x30
<br>? drm_ioctl+0x296/0x4b0
<br>? __pfx_drm_mode_atomic_ioctl+0x10/0x10
<br>drm_ioctl_kernel+0xcd/0x170
<br>drm_ioctl+0x26d/0x4b0
<br>? __pfx_drm_mode_atomic_ioctl+0x10/0x10
<br>amdgpu_drm_ioctl+0x4e/0x90 [amdgpu 62e600d2a75e9158e1cd0a243bdc8e6da040c054]
<br>__x64_sys_ioctl+0x94/0xd0
<br>do_syscall_64+0x60/0x90
<br>? do_syscall_64+0x6c/0x90
<br>entry_SYSCALL_64_after_hwframe+0x72/0xdc
<br>RIP: 0033:0x7f4dad17f76f
<br>Code: 00 48 89 44 24 18 31 c0 48 8d 44 24 60 c7 04 24 10 00 00 00 48 89
44 24 08 48 8d 44 24 20 48 89 44 24 10 b8 10 00 00 00 0f 05 &lt;89&gt;
c&gt;
<br>RSP: 002b:00007ffd9ae859f0 EFLAGS: 00000246 ORIG_RAX: 0000000000000010
<br>RAX: ffffffffffffffda RBX: 000055e255a55900 RCX: 00007f4dad17f76f
<br>RDX: 00007ffd9ae85a90 RSI: 00000000c03864bc RDI: 000000000000000b
<br>RBP: 00007ffd9ae85a90 R08: 0000000000000003 R09: 0000000000000003
<br>R10: 0000000000000000 R11: 0000000000000246 R12: 00000000c03864bc
<br>R13: 000000000000000b R14: 000055e255a7fc60 R15: 000055e255a01eb0
<br>&lt;/TASK&gt;
<br>Modules linked in: rfcomm snd_seq_dummy snd_hrtimer snd_seq snd_seq_device
ccm cmac algif_hash algif_skcipher af_alg joydev mousedev bnep &gt;
<br>typec libphy k10temp ipmi_msghandler roles i2c_scmi acpi_cpufreq mac_hid
nft_reject_inet nf_reject_ipv4 nf_reject_ipv6 nft_reject nft_mas&gt;
<br>CR2: 0000000000000008
<br>---[ end trace 0000000000000000 ]---
<br>RIP: 0010:drm_dp_atomic_find_time_slots+0x5e/0x260 [drm_display_helper]
<br>Code: 01 00 00 48 8b 85 60 05 00 00 48 63 80 88 00 00 00 3b 43 28 0f 8d
2e 01 00 00 48 8b 53 30 48 8d 04 80 48 8d 04 c2 48 8b 40 18 &lt;48&gt;
8&gt;
<br>RSP: 0018:ffff960cc2df77d8 EFLAGS: 00010293
<br>RAX: 0000000000000000 RBX: ffff8afb87e81280 RCX: 0000000000000224
<br>RDX: ffff8afb9ee37c00 RSI: ffff8afb8da1a578 RDI: ffff8afb87e81280
<br>RBP: ffff8afb83d67000 R08: 0000000000000001 R09: ffff8afb9652f850
<br>R10: ffff960cc2df7908 R11: 0000000000000002 R12: 0000000000000000
<br>R13: ffff8afb8d7688a0 R14: ffff8afb8da1a578 R15: 0000000000000224
<br>FS: 00007f4dac35ce00(0000) GS:ffff8afe30b00000(0000
<br>---truncated---</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26700</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26699</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>drm/amd/display: Fix array-index-out-of-bounds in dcn35_clkmgr
<br>
<br>[Why]
<br>There is a potential memory access violation while
<br>iterating through array of dcn35 clks.
<br>
<br>[How]
<br>Limit iteration per array size.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26699</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26698</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>hv_netvsc: Fix race condition between netvsc_probe and netvsc_remove
<br>
<br>In commit ac5047671758 ("hv_netvsc: Disable NAPI before closing the
<br>VMBus channel"), napi_disable was getting called for all channels,
<br>including all subchannels without confirming if they are enabled or not.
<br>
<br>This caused hv_netvsc getting hung at napi_disable, when netvsc_probe()
<br>has finished running but nvdev-&gt;subchan_work has not started yet.
<br>netvsc_subchan_work() -&gt; rndis_set_subchannel() has not created the
<br>sub-channels and because of that netvsc_sc_open() is not running.
<br>netvsc_remove() calls cancel_work_sync(&amp;nvdev-&gt;subchan_work), for
which
<br>netvsc_subchan_work did not run.
<br>
<br>netif_napi_add() sets the bit NAPI_STATE_SCHED because it ensures NAPI
<br>cannot be scheduled. Then netvsc_sc_open() -&gt; napi_enable will clear
the
<br>NAPIF_STATE_SCHED bit, so it can be scheduled. napi_disable() does the
<br>opposite.
<br>
<br>Now during netvsc_device_remove(), when napi_disable is called for those
<br>subchannels, napi_disable gets stuck on infinite msleep.
<br>
<br>This fix addresses this problem by ensuring that napi_disable() is not
<br>getting called for non-enabled NAPI struct.
<br>But netif_napi_del() is still necessary for these non-enabled NAPI struct
<br>for cleanup purpose.
<br>
<br>Call trace:
<br>[ 654.559417] task:modprobe state:D stack: 0 pid: 2321 ppid: 1091 flags:0x00004002
<br>[ 654.568030] Call Trace:
<br>[ 654.571221] &lt;TASK&gt;
<br>[ 654.573790] __schedule+0x2d6/0x960
<br>[ 654.577733] schedule+0x69/0xf0
<br>[ 654.581214] schedule_timeout+0x87/0x140
<br>[ 654.585463] ? __bpf_trace_tick_stop+0x20/0x20
<br>[ 654.590291] msleep+0x2d/0x40
<br>[ 654.593625] napi_disable+0x2b/0x80
<br>[ 654.597437] netvsc_device_remove+0x8a/0x1f0 [hv_netvsc]
<br>[ 654.603935] rndis_filter_device_remove+0x194/0x1c0 [hv_netvsc]
<br>[ 654.611101] ? do_wait_intr+0xb0/0xb0
<br>[ 654.615753] netvsc_remove+0x7c/0x120 [hv_netvsc]
<br>[ 654.621675] vmbus_remove+0x27/0x40 [hv_vmbus]</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26698</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26697</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>nilfs2: fix data corruption in dsync block recovery for small block sizes
<br>
<br>The helper function nilfs_recovery_copy_block() of
<br>nilfs_recovery_dsync_blocks(), which recovers data from logs created by
<br>data sync writes during a mount after an unclean shutdown, incorrectly
<br>calculates the on-page offset when copying repair data to the file's page
<br>cache. In environments where the block size is smaller than the page
<br>size, this flaw can cause data corruption and leak uninitialized memory
<br>bytes during the recovery process.
<br>
<br>Fix these issues by correcting this byte offset calculation on the page.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26697</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26696</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>nilfs2: fix hang in nilfs_lookup_dirty_data_buffers()
<br>
<br>Syzbot reported a hang issue in migrate_pages_batch() called by mbind()
<br>and nilfs_lookup_dirty_data_buffers() called in the log writer of nilfs2.
<br>
<br>While migrate_pages_batch() locks a folio and waits for the writeback
to
<br>complete, the log writer thread that should bring the writeback to
<br>completion picks up the folio being written back in
<br>nilfs_lookup_dirty_data_buffers() that it calls for subsequent log
<br>creation and was trying to lock the folio. Thus causing a deadlock.
<br>
<br>In the first place, it is unexpected that folios/pages in the middle of
<br>writeback will be updated and become dirty. Nilfs2 adds a checksum to
<br>verify the validity of the log being written and uses it for recovery
at
<br>mount, so data changes during writeback are suppressed. Since this is
<br>broken, an unclean shutdown could potentially cause recovery to fail.
<br>
<br>Investigation revealed that the root cause is that the wait for writeback
<br>completion in nilfs_page_mkwrite() is conditional, and if the backing
<br>device does not require stable writes, data may be modified without
<br>waiting.
<br>
<br>Fix these issues by making nilfs_page_mkwrite() wait for writeback to
<br>finish regardless of the stable write requirement of the backing device.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26696</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26695</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>crypto: ccp - Fix null pointer dereference in __sev_platform_shutdown_locked
<br>
<br>The SEV platform device can be shutdown with a null psp_master,
<br>e.g., using DEBUG_TEST_DRIVER_REMOVE. Found using KASAN:
<br>
<br>[ 137.148210] ccp 0000:23:00.1: enabling device (0000 -&gt; 0002)
<br>[ 137.162647] ccp 0000:23:00.1: no command queues available
<br>[ 137.170598] ccp 0000:23:00.1: sev enabled
<br>[ 137.174645] ccp 0000:23:00.1: psp enabled
<br>[ 137.178890] general protection fault, probably for non-canonical address
0xdffffc000000001e: 0000 [#1] PREEMPT SMP DEBUG_PAGEALLOC KASAN NOPTI
<br>[ 137.182693] KASAN: null-ptr-deref in range [0x00000000000000f0-0x00000000000000f7]
<br>[ 137.182693] CPU: 93 PID: 1 Comm: swapper/0 Not tainted 6.8.0-rc1+ #311
<br>[ 137.182693] RIP: 0010:__sev_platform_shutdown_locked+0x51/0x180
<br>[ 137.182693] Code: 08 80 3c 08 00 0f 85 0e 01 00 00 48 8b 1d 67 b6 01
08 48 b8 00 00 00 00 00 fc ff df 48 8d bb f0 00 00 00 48 89 f9 48 c1 e9
03 &lt;80&gt; 3c 01 00 0f 85 fe 00 00 00 48 8b 9b f0 00 00 00 48 85 db
74 2c
<br>[ 137.182693] RSP: 0018:ffffc900000cf9b0 EFLAGS: 00010216
<br>[ 137.182693] RAX: dffffc0000000000 RBX: 0000000000000000 RCX: 000000000000001e
<br>[ 137.182693] RDX: 0000000000000000 RSI: 0000000000000008 RDI: 00000000000000f0
<br>[ 137.182693] RBP: ffffc900000cf9c8 R08: 0000000000000000 R09: fffffbfff58f5a66
<br>[ 137.182693] R10: ffffc900000cf9c8 R11: ffffffffac7ad32f R12: ffff8881e5052c28
<br>[ 137.182693] R13: ffff8881e5052c28 R14: ffff8881758e43e8 R15: ffffffffac64abf8
<br>[ 137.182693] FS: 0000000000000000(0000) GS:ffff889de7000000(0000) knlGS:0000000000000000
<br>[ 137.182693] CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033
<br>[ 137.182693] CR2: 0000000000000000 CR3: 0000001cf7c7e000 CR4: 0000000000350ef0
<br>[ 137.182693] Call Trace:
<br>[ 137.182693] &lt;TASK&gt;
<br>[ 137.182693] ? show_regs+0x6c/0x80
<br>[ 137.182693] ? __die_body+0x24/0x70
<br>[ 137.182693] ? die_addr+0x4b/0x80
<br>[ 137.182693] ? exc_general_protection+0x126/0x230
<br>[ 137.182693] ? asm_exc_general_protection+0x2b/0x30
<br>[ 137.182693] ? __sev_platform_shutdown_locked+0x51/0x180
<br>[ 137.182693] sev_firmware_shutdown.isra.0+0x1e/0x80
<br>[ 137.182693] sev_dev_destroy+0x49/0x100
<br>[ 137.182693] psp_dev_destroy+0x47/0xb0
<br>[ 137.182693] sp_destroy+0xbb/0x240
<br>[ 137.182693] sp_pci_remove+0x45/0x60
<br>[ 137.182693] pci_device_remove+0xaa/0x1d0
<br>[ 137.182693] device_remove+0xc7/0x170
<br>[ 137.182693] really_probe+0x374/0xbe0
<br>[ 137.182693] ? srso_return_thunk+0x5/0x5f
<br>[ 137.182693] __driver_probe_device+0x199/0x460
<br>[ 137.182693] driver_probe_device+0x4e/0xd0
<br>[ 137.182693] __driver_attach+0x191/0x3d0
<br>[ 137.182693] ? <strong>pfx</strong>_driver_attach+0x10/0x10
<br>[ 137.182693] bus_for_each_dev+0x100/0x190
<br>[ 137.182693] ? __pfx_bus_for_each_dev+0x10/0x10
<br>[ 137.182693] ? __kasan_check_read+0x15/0x20
<br>[ 137.182693] ? srso_return_thunk+0x5/0x5f
<br>[ 137.182693] ? <em>raw</em>spin_unlock+0x27/0x50
<br>[ 137.182693] driver_attach+0x41/0x60
<br>[ 137.182693] bus_add_driver+0x2a8/0x580
<br>[ 137.182693] driver_register+0x141/0x480
<br>[ 137.182693] __pci_register_driver+0x1d6/0x2a0
<br>[ 137.182693] ? srso_return_thunk+0x5/0x5f
<br>[ 137.182693] ? esrt_sysfs_init+0x1cd/0x5d0
<br>[ 137.182693] ? __pfx_sp_mod_init+0x10/0x10
<br>[ 137.182693] sp_pci_init+0x22/0x30
<br>[ 137.182693] sp_mod_init+0x14/0x30
<br>[ 137.182693] ? __pfx_sp_mod_init+0x10/0x10
<br>[ 137.182693] do_one_initcall+0xd1/0x470
<br>[ 137.182693] ? __pfx_do_one_initcall+0x10/0x10
<br>[ 137.182693] ? parameq+0x80/0xf0
<br>[ 137.182693] ? srso_return_thunk+0x5/0x5f
<br>[ 137.182693] ? __kmalloc+0x3b0/0x4e0
<br>[ 137.182693] ? kernel_init_freeable+0x92d/0x1050
<br>[ 137.182693] ? kasan_populate_vmalloc_pte+0x171/0x190
<br>[ 137.182693] ? srso_return_thunk+0x5/0x5f
<br>[ 137.182693] kernel_init_freeable+0xa64/0x1050
<br>[ 137.182693] ? __pfx_kernel_init+0x10/0x10
<br>[ 137.182693] kernel_init+0x24/0x160
<br>[ 137.182693] ? __switch_to_asm+0x3e/0x70
<br>[ 137.182693] ret_from_fork+0x40/0x80
<br>[ 137.182693] ? __pfx_kernel_init+0x1
<br>---truncated---</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26695</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26694</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>wifi: iwlwifi: fix double-free bug
<br>
<br>The storage for the TLV PC register data wasn't done like all
<br>the other storage in the drv-&gt;fw area, which is cleared at the
<br>end of deallocation. Therefore, the freeing must also be done
<br>differently, explicitly NULL'ing it out after the free, since
<br>otherwise there's a nasty double-free bug here if a file fails
<br>to load after this has been parsed, and we get another free
<br>later (e.g. because no other file exists.) Fix that by adding
<br>the missing NULL assignment.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26694</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26693</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>wifi: iwlwifi: mvm: fix a crash when we run out of stations
<br>
<br>A DoS tool that injects loads of authentication frames made our AP
<br>crash. The iwl_mvm_is_dup() function couldn't find the per-queue
<br>dup_data which was not allocated.
<br>
<br>The root cause for that is that we ran out of stations in the firmware
<br>and we didn't really add the station to the firmware, yet we didn't
<br>return an error to mac80211.
<br>Mac80211 was thinking that we have the station and because of that,
<br>sta_info::uploaded was set to 1. This allowed
<br>ieee80211_find_sta_by_ifaddr() to return a valid station object, but
<br>that ieee80211_sta didn't have any iwl_mvm_sta object initialized and
<br>that caused the crash mentioned earlier when we got Rx on that station.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26693</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26692</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>smb: Fix regression in writes when non-standard maximum write size negotiated
<br>
<br>The conversion to netfs in the 6.3 kernel caused a regression when
<br>maximum write size is set by the server to an unexpected value which is
<br>not a multiple of 4096 (similarly if the user overrides the maximum
<br>write size by setting mount parm "wsize", but sets it to a value that
<br>is not a multiple of 4096). When negotiated write size is not a
<br>multiple of 4096 the netfs code can skip the end of the final
<br>page when doing large sequential writes, causing data corruption.
<br>
<br>This section of code is being rewritten/removed due to a large
<br>netfs change, but until that point (ie for the 6.3 kernel until now)
<br>we can not support non-standard maximum write sizes.
<br>
<br>Add a warning if a user specifies a wsize on mount that is not
<br>a multiple of 4096 (and round down), also add a change where we
<br>round down the maximum write size if the server negotiates a value
<br>that is not a multiple of 4096 (we also have to check to make sure that
<br>we do not round it down to zero).</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26692</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26691</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>KVM: arm64: Fix circular locking dependency
<br>
<br>The rule inside kvm enforces that the vcpu-&gt;mutex is taken <em>inside</em>
<br>kvm-&gt;lock. The rule is violated by the pkvm_create_hyp_vm() which acquires
<br>the kvm-&gt;lock while already holding the vcpu-&gt;mutex lock from
<br>kvm_vcpu_ioctl(). Avoid the circular locking dependency altogether by
<br>protecting the hyp vm handle with the config_lock, much like we already
<br>do for other forms of VM-scoped data.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26691</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26690</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>net: stmmac: protect updates of 64-bit statistics counters
<br>
<br>As explained by a comment in &lt;linux/u64_stats_sync.h&gt;, write side
of struct
<br>u64_stats_sync must ensure mutual exclusion, or one seqcount update could
<br>be lost on 32-bit platforms, thus blocking readers forever. Such lockups
<br>have been observed in real world after stmmac_xmit() on one CPU raced
with
<br>stmmac_napi_poll_tx() on another CPU.
<br>
<br>To fix the issue without introducing a new lock, split the statics into
<br>three parts:
<br>
<br>1. fields updated only under the tx queue lock,
<br>2. fields updated only during NAPI poll,
<br>3. fields updated only from interrupt context,
<br>
<br>Updates to fields in the first two groups are already serialized through
<br>other locks. It is sufficient to split the existing struct u64_stats_sync
<br>so that each group has its own.
<br>
<br>Note that tx_set_ic_bit is updated from both contexts. Split this counter
<br>so that each context gets its own, and calculate their sum to get the
total
<br>value in stmmac_get_ethtool_stats().
<br>
<br>For the third group, multiple interrupts may be processed by different
CPUs
<br>at the same time, but interrupts on the same CPU will not nest. Move fields
<br>from this group to a newly created per-cpu struct stmmac_pcpu_stats.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26690</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26689</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>ceph: prevent use-after-free in encode_cap_msg()
<br>
<br>In fs/ceph/caps.c, in encode_cap_msg(), "use after free" error was
<br>caught by KASAN at this line - 'ceph_buffer_get(arg-&gt;xattr_buf);'.
This
<br>implies before the refcount could be increment here, it was freed.
<br>
<br>In same file, in "handle_cap_grant()" refcount is decremented by this
<br>line - 'ceph_buffer_put(ci-&gt;i_xattrs.blob);'. It appears that a race
<br>occurred and resource was freed by the latter line before the former
<br>line could increment it.
<br>
<br>encode_cap_msg() is called by __send_cap() and __send_cap() is called
by
<br>ceph_check_caps() after calling __prep_cap(). __prep_cap() is where
<br>arg-&gt;xattr_buf is assigned to ci-&gt;i_xattrs.blob. This is the spot
where
<br>the refcount must be increased to prevent "use after free" error.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26689</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26688</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>fs,hugetlb: fix NULL pointer dereference in hugetlbs_fill_super
<br>
<br>When configuring a hugetlb filesystem via the fsconfig() syscall, there
is
<br>a possible NULL dereference in hugetlbfs_fill_super() caused by assigning
<br>NULL to ctx-&gt;hstate in hugetlbfs_parse_param() when the requested pagesize
<br>is non valid.
<br>
<br>E.g: Taking the following steps:
<br>
<br>fd = fsopen("hugetlbfs", FSOPEN_CLOEXEC);
<br>fsconfig(fd, FSCONFIG_SET_STRING, "pagesize", "1024", 0);
<br>fsconfig(fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
<br>
<br>Given that the requested "pagesize" is invalid, ctxt-&gt;hstate will be
replaced
<br>with NULL, losing its previous value, and we will print an error:
<br>
<br>...
<br>...
<br>case Opt_pagesize:
<br>ps = memparse(param-&gt;string, &amp;rest);
<br>ctx-&gt;hstate = h;
<br>if (!ctx-&gt;hstate) {
<br>pr_err("Unsupported page size %lu MB\
<br>", ps / SZ_1M);
<br>return -EINVAL;
<br>}
<br>return 0;
<br>...
<br>...
<br>
<br>This is a problem because later on, we will dereference ctxt-&gt;hstate
in
<br>hugetlbfs_fill_super()
<br>
<br>...
<br>...
<br>sb-&gt;s_blocksize = huge_page_size(ctx-&gt;hstate);
<br>...
<br>...
<br>
<br>Causing below Oops.
<br>
<br>Fix this by replacing cxt-&gt;hstate value only when then pagesize is
known
<br>to be valid.
<br>
<br>kernel: hugetlbfs: Unsupported page size 0 MB
<br>kernel: BUG: kernel NULL pointer dereference, address: 0000000000000028
<br>kernel: #PF: supervisor read access in kernel mode
<br>kernel: #PF: error_code(0x0000) - not-present page
<br>kernel: PGD 800000010f66c067 P4D 800000010f66c067 PUD 1b22f8067 PMD 0
<br>kernel: Oops: 0000 [#1] PREEMPT SMP PTI
<br>kernel: CPU: 4 PID: 5659 Comm: syscall Tainted: G E 6.8.0-rc2-default+
#22 5a47c3fef76212addcc6eb71344aabc35190ae8f
<br>kernel: Hardware name: Intel Corp. GROVEPORT/GROVEPORT, BIOS GVPRCRB1.86B.0016.D04.1705030402
05/03/2017
<br>kernel: RIP: 0010:hugetlbfs_fill_super+0xb4/0x1a0
<br>kernel: Code: 48 8b 3b e8 3e c6 ed ff 48 85 c0 48 89 45 20 0f 84 d6 00
00 00 48 b8 ff ff ff ff ff ff ff 7f 4c 89 e7 49 89 44 24 20 48 8b 03 &lt;8b&gt;
48 28 b8 00 10 00 00 48 d3 e0 49 89 44 24 18 48 8b 03 8b 40 28
<br>kernel: RSP: 0018:ffffbe9960fcbd48 EFLAGS: 00010246
<br>kernel: RAX: 0000000000000000 RBX: ffff9af5272ae780 RCX: 0000000000372004
<br>kernel: RDX: ffffffffffffffff RSI: ffffffffffffffff RDI: ffff9af555e9b000
<br>kernel: RBP: ffff9af52ee66b00 R08: 0000000000000040 R09: 0000000000370004
<br>kernel: R10: ffffbe9960fcbd48 R11: 0000000000000040 R12: ffff9af555e9b000
<br>kernel: R13: ffffffffa66b86c0 R14: ffff9af507d2f400 R15: ffff9af507d2f400
<br>kernel: FS: 00007ffbc0ba4740(0000) GS:ffff9b0bd7000000(0000) knlGS:0000000000000000
<br>kernel: CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033
<br>kernel: CR2: 0000000000000028 CR3: 00000001b1ee0000 CR4: 00000000001506f0
<br>kernel: Call Trace:
<br>kernel: &lt;TASK&gt;
<br>kernel: ? __die_body+0x1a/0x60
<br>kernel: ? page_fault_oops+0x16f/0x4a0
<br>kernel: ? search_bpf_extables+0x65/0x70
<br>kernel: ? fixup_exception+0x22/0x310
<br>kernel: ? exc_page_fault+0x69/0x150
<br>kernel: ? asm_exc_page_fault+0x22/0x30
<br>kernel: ? __pfx_hugetlbfs_fill_super+0x10/0x10
<br>kernel: ? hugetlbfs_fill_super+0xb4/0x1a0
<br>kernel: ? hugetlbfs_fill_super+0x28/0x1a0
<br>kernel: ? __pfx_hugetlbfs_fill_super+0x10/0x10
<br>kernel: vfs_get_super+0x40/0xa0
<br>kernel: ? __pfx_bpf_lsm_capable+0x10/0x10
<br>kernel: vfs_get_tree+0x25/0xd0
<br>kernel: vfs_cmd_create+0x64/0xe0
<br>kernel: __x64_sys_fsconfig+0x395/0x410
<br>kernel: do_syscall_64+0x80/0x160
<br>kernel: ? syscall_exit_to_user_mode+0x82/0x240
<br>kernel: ? do_syscall_64+0x8d/0x160
<br>kernel: ? syscall_exit_to_user_mode+0x82/0x240
<br>kernel: ? do_syscall_64+0x8d/0x160
<br>kernel: ? exc_page_fault+0x69/0x150
<br>kernel: entry_SYSCALL_64_after_hwframe+0x6e/0x76
<br>kernel: RIP: 0033:0x7ffbc0cb87c9
<br>kernel: Code: 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 66 90 48 89
f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 &lt;48&gt;
3d 01 f0 ff ff 73 01 c3 48 8b 0d 97 96 0d 00 f7 d8 64 89 01 48
<br>kernel: RSP: 002b:00007ffc29d2f388 EFLAGS: 00000206 ORIG_RAX: 00000000000001af
<br>kernel: RAX: fffffffffff
<br>---truncated---</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26688</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26687</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>xen/events: close evtchn after mapping cleanup
<br>
<br>shutdown_pirq and startup_pirq are not taking the
<br>irq_mapping_update_lock because they can't due to lock inversion. Both
<br>are called with the irq_desc-&gt;lock being taking. The lock order,
<br>however, is first irq_mapping_update_lock and then irq_desc-&gt;lock.
<br>
<br>This opens multiple races:
<br>- shutdown_pirq can be interrupted by a function that allocates an event
<br>channel:
<br>
<br>CPU0 CPU1
<br>shutdown_pirq {
<br>xen_evtchn_close(e)
<br>__startup_pirq {
<br>EVTCHNOP_bind_pirq
<br>-&gt; returns just freed evtchn e
<br>set_evtchn_to_irq(e, irq)
<br>}
<br>xen_irq_info_cleanup() {
<br>set_evtchn_to_irq(e, -1)
<br>}
<br>}
<br>
<br>Assume here event channel e refers here to the same event channel
<br>number.
<br>After this race the evtchn_to_irq mapping for e is invalid (-1).
<br>
<br>- __startup_pirq races with __unbind_from_irq in a similar way. Because
<br>__startup_pirq doesn't take irq_mapping_update_lock it can grab the
<br>evtchn that __unbind_from_irq is currently freeing and cleaning up. In
<br>this case even though the event channel is allocated, its mapping can
<br>be unset in evtchn_to_irq.
<br>
<br>The fix is to first cleanup the mappings and then close the event
<br>channel. In this way, when an event channel gets allocated it's
<br>potential previous evtchn_to_irq mappings are guaranteed to be unset already.
<br>This is also the reverse order of the allocation where first the event
<br>channel is allocated and then the mappings are setup.
<br>
<br>On a 5.10 kernel prior to commit 3fcdaf3d7634 ("xen/events: modify internal
<br>[un]bind interfaces"), we hit a BUG like the following during probing
of NVMe
<br>devices. The issue is that during nvme_setup_io_queues, pci_free_irq
<br>is called for every device which results in a call to shutdown_pirq.
<br>With many nvme devices it's therefore likely to hit this race during
<br>boot because there will be multiple calls to shutdown_pirq and
<br>startup_pirq are running potentially in parallel.
<br>
<br>------------[ cut here ]------------
<br>blkfront: xvda: barrier or flush: disabled; persistent grants: enabled;
indirect descriptors: enabled; bounce buffer: enabled
<br>kernel BUG at drivers/xen/events/events_base.c:499!
<br>invalid opcode: 0000 [#1] SMP PTI
<br>CPU: 44 PID: 375 Comm: kworker/u257:23 Not tainted 5.10.201-191.748.amzn2.x86_64
#1
<br>Hardware name: Xen HVM domU, BIOS <a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">4.11.amazon</a> 08/24/2006
<br>Workqueue: nvme-reset-wq nvme_reset_work
<br>RIP: 0010:bind_evtchn_to_cpu+0xdf/0xf0
<br>Code: 5d 41 5e c3 cc cc cc cc 44 89 f7 e8 2b 55 ad ff 49 89 c5 48 85 c0
0f 84 64 ff ff ff 4c 8b 68 30 41 83 fe ff 0f 85 60 ff ff ff &lt;0f&gt;
0b 66 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 40 00 0f 1f 44 00 00
<br>RSP: 0000:ffffc9000d533b08 EFLAGS: 00010046
<br>RAX: 0000000000000000 RBX: 0000000000000000 RCX: 0000000000000006
<br>RDX: 0000000000000028 RSI: 00000000ffffffff RDI: 00000000ffffffff
<br>RBP: ffff888107419680 R08: 0000000000000000 R09: ffffffff82d72b00
<br>R10: 0000000000000000 R11: 0000000000000000 R12: 00000000000001ed
<br>R13: 0000000000000000 R14: 00000000ffffffff R15: 0000000000000002
<br>FS: 0000000000000000(0000) GS:ffff88bc8b500000(0000) knlGS:0000000000000000
<br>CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033
<br>CR2: 0000000000000000 CR3: 0000000002610001 CR4: 00000000001706e0
<br>DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
<br>DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
<br>Call Trace:
<br>? show_trace_log_lvl+0x1c1/0x2d9
<br>? show_trace_log_lvl+0x1c1/0x2d9
<br>? set_affinity_irq+0xdc/0x1c0
<br>? __die_body.cold+0x8/0xd
<br>? die+0x2b/0x50
<br>? do_trap+0x90/0x110
<br>? bind_evtchn_to_cpu+0xdf/0xf0
<br>? do_error_trap+0x65/0x80
<br>? bind_evtchn_to_cpu+0xdf/0xf0
<br>? exc_invalid_op+0x4e/0x70
<br>? bind_evtchn_to_cpu+0xdf/0xf0
<br>? asm_exc_invalid_op+0x12/0x20
<br>? bind_evtchn_to_cpu+0xdf/0x
<br>---truncated---</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26687</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26686</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>fs/proc: do_task_stat: use sig-&gt;stats_lock to gather the threads/children
stats
<br>
<br>lock_task_sighand() can trigger a hard lockup. If NR_CPUS threads call
<br>do_task_stat() at the same time and the process has NR_THREADS, it will
<br>spin with irqs disabled O(NR_CPUS * NR_THREADS) time.
<br>
<br>Change do_task_stat() to use sig-&gt;stats_lock to gather the statistics
<br>outside of -&gt;siglock protected section, in the likely case this code
will
<br>run lockless.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26686</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26685</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>nilfs2: fix potential bug in end_buffer_async_write
<br>
<br>According to a syzbot report, end_buffer_async_write(), which handles
the
<br>completion of block device writes, may detect abnormal condition of the
<br>buffer async_write flag and cause a BUG_ON failure when using nilfs2.
<br>
<br>Nilfs2 itself does not use end_buffer_async_write(). But, the async_write
<br>flag is now used as a marker by commit 7f42ec394156 ("nilfs2: fix issue
<br>with race condition of competition between segments for dirty blocks")
as
<br>a means of resolving double list insertion of dirty blocks in
<br>nilfs_lookup_dirty_data_buffers() and nilfs_lookup_node_buffers() and
the
<br>resulting crash.
<br>
<br>This modification is safe as long as it is used for file data and b-tree
<br>node blocks where the page caches are independent. However, it was
<br>irrelevant and redundant to also introduce async_write for segment summary
<br>and super root blocks that share buffers with the backing device. This
<br>led to the possibility that the BUG_ON check in end_buffer_async_write
<br>would fail as described above, if independent writebacks of the backing
<br>device occurred in parallel.
<br>
<br>The use of async_write for segment summary buffers has already been
<br>removed in a previous change.
<br>
<br>Fix this issue by removing the manipulation of the async_write flag for
<br>the remaining super root block buffer.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26685</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52639</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>KVM: s390: vsie: fix race during shadow creation
<br>
<br>Right now it is possible to see gmap-&gt;private being zero in
<br>kvm_s390_vsie_gmap_notifier resulting in a crash. This is due to the
<br>fact that we add gmap-&gt;private == kvm after creation:
<br>
<br>static int acquire_gmap_shadow(struct kvm_vcpu <em>vcpu,<br>struct vsie_page </em>vsie_page)
<br>{
<br>[...]
<br>gmap = gmap_shadow(vcpu-&gt;arch.gmap, asce, edat);
<br>if (IS_ERR(gmap))
<br>return PTR_ERR(gmap);
<br>gmap-&gt;private = vcpu-&gt;kvm;
<br>
<br>Let children inherit the private field of the parent.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52639</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52638</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>can: j1939: prevent deadlock by changing j1939_socks_lock to rwlock
<br>
<br>The following 3 locks would race against each other, causing the
<br>deadlock situation in the Syzbot bug report:
<br>
<br>- j1939_socks_lock
<br>- active_session_list_lock
<br>- sk_session_queue_lock
<br>
<br>A reasonable fix is to change j1939_socks_lock to an rwlock, since in
<br>the rare situations where a write lock is required for the linked list
<br>that j1939_socks_lock is protecting, the code does not attempt to
<br>acquire any more locks. This would break the circular lock dependency,
<br>where, for example, the current thread already locks j1939_socks_lock
<br>and attempts to acquire sk_session_queue_lock, and at the same time,
<br>another thread attempts to acquire j1939_socks_lock while holding
<br>sk_session_queue_lock.
<br>
<br>NOTE: This patch along does not fix the unregister_netdevice bug
<br>reported by Syzbot; instead, it solves a deadlock situation to prepare
<br>for one or more further patches to actually fix the Syzbot bug, which
<br>appears to be a reference counting problem within the j1939 codebase.
<br>
<br>[mkl: remove unrelated newline change]</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52638</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-52637</p>
</td>
<td rowspan="1" colspan="1">
<p>In the Linux kernel, the following vulnerability has been resolved:
<br>
<br>can: j1939: Fix UAF in j1939_sk_match_filter during setsockopt(SO_J1939_FILTER)
<br>
<br>Lock jsk-&gt;sk to prevent UAF when setsockopt(..., SO_J1939_FILTER, ...)
<br>modifies jsk-&gt;filters while receiving packets.
<br>
<br>Following trace was seen on affected system:
<br>==================================================================
<br>BUG: KASAN: slab-use-after-free in j1939_sk_recv_match_one+0x1af/0x2d0
[can_j1939]
<br>Read of size 4 at addr ffff888012144014 by task j1939/350
<br>
<br>CPU: 0 PID: 350 Comm: j1939 Tainted: G W OE 6.5.0-rc5 #1
<br>Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1.1
04/01/2014
<br>Call Trace:
<br>print_report+0xd3/0x620
<br>? kasan_complete_mode_report_info+0x7d/0x200
<br>? j1939_sk_recv_match_one+0x1af/0x2d0 [can_j1939]
<br>kasan_report+0xc2/0x100
<br>? j1939_sk_recv_match_one+0x1af/0x2d0 [can_j1939]
<br>__asan_load4+0x84/0xb0
<br>j1939_sk_recv_match_one+0x1af/0x2d0 [can_j1939]
<br>j1939_sk_recv+0x20b/0x320 [can_j1939]
<br>? __kasan_check_write+0x18/0x20
<br>? __pfx_j1939_sk_recv+0x10/0x10 [can_j1939]
<br>? j1939_simple_recv+0x69/0x280 [can_j1939]
<br>? j1939_ac_recv+0x5e/0x310 [can_j1939]
<br>j1939_can_recv+0x43f/0x580 [can_j1939]
<br>? __pfx_j1939_can_recv+0x10/0x10 [can_j1939]
<br>? raw_rcv+0x42/0x3c0 [can_raw]
<br>? __pfx_j1939_can_recv+0x10/0x10 [can_j1939]
<br>can_rcv_filter+0x11f/0x350 [can]
<br>can_receive+0x12f/0x190 [can]
<br>? __pfx_can_rcv+0x10/0x10 [can]
<br>can_rcv+0xdd/0x130 [can]
<br>? __pfx_can_rcv+0x10/0x10 [can]
<br>__netif_receive_skb_one_core+0x13d/0x150
<br>? <strong>pfx</strong>_netif_receive_skb_one_core+0x10/0x10
<br>? __kasan_check_write+0x18/0x20
<br>? <em>raw</em>spin_lock_irq+0x8c/0xe0
<br>__netif_receive_skb+0x23/0xb0
<br>process_backlog+0x107/0x260
<br>__napi_poll+0x69/0x310
<br>net_rx_action+0x2a1/0x580
<br>? __pfx_net_rx_action+0x10/0x10
<br>? <strong>pfx</strong>raw_spin_lock+0x10/0x10
<br>? handle_irq_event+0x7d/0xa0
<br>__do_softirq+0xf3/0x3f8
<br>do_softirq+0x53/0x80
<br>&lt;/IRQ&gt;
<br>&lt;TASK&gt;
<br>__local_bh_enable_ip+0x6e/0x70
<br>netif_rx+0x16b/0x180
<br>can_send+0x32b/0x520 [can]
<br>? __pfx_can_send+0x10/0x10 [can]
<br>? __check_object_size+0x299/0x410
<br>raw_sendmsg+0x572/0x6d0 [can_raw]
<br>? __pfx_raw_sendmsg+0x10/0x10 [can_raw]
<br>? apparmor_socket_sendmsg+0x2f/0x40
<br>? __pfx_raw_sendmsg+0x10/0x10 [can_raw]
<br>sock_sendmsg+0xef/0x100
<br>sock_write_iter+0x162/0x220
<br>? __pfx_sock_write_iter+0x10/0x10
<br>? __rtnl_unlock+0x47/0x80
<br>? security_file_permission+0x54/0x320
<br>vfs_write+0x6ba/0x750
<br>? __pfx_vfs_write+0x10/0x10
<br>? __fget_light+0x1ca/0x1f0
<br>? __rcu_read_unlock+0x5b/0x280
<br>ksys_write+0x143/0x170
<br>? __pfx_ksys_write+0x10/0x10
<br>? __kasan_check_read+0x15/0x20
<br>? fpregs_assert_state_consistent+0x62/0x70
<br>__x64_sys_write+0x47/0x60
<br>do_syscall_64+0x60/0x90
<br>? do_syscall_64+0x6d/0x90
<br>? irqentry_exit+0x3f/0x50
<br>? exc_page_fault+0x79/0xf0
<br>entry_SYSCALL_64_after_hwframe+0x6e/0xd8
<br>
<br>Allocated by task 348:
<br>kasan_save_stack+0x2a/0x50
<br>kasan_set_track+0x29/0x40
<br>kasan_save_alloc_info+0x1f/0x30
<br>__kasan_kmalloc+0xb5/0xc0
<br>__kmalloc_node_track_caller+0x67/0x160
<br>j1939_sk_setsockopt+0x284/0x450 [can_j1939]
<br>__sys_setsockopt+0x15c/0x2f0
<br>__x64_sys_setsockopt+0x6b/0x80
<br>do_syscall_64+0x60/0x90
<br>entry_SYSCALL_64_after_hwframe+0x6e/0xd8
<br>
<br>Freed by task 349:
<br>kasan_save_stack+0x2a/0x50
<br>kasan_set_track+0x29/0x40
<br>kasan_save_free_info+0x2f/0x50
<br>__kasan_slab_free+0x12e/0x1c0
<br>__kmem_cache_free+0x1b9/0x380
<br>kfree+0x7a/0x120
<br>j1939_sk_setsockopt+0x3b2/0x450 [can_j1939]
<br>__sys_setsockopt+0x15c/0x2f0
<br>__x64_sys_setsockopt+0x6b/0x80
<br>do_syscall_64+0x60/0x90
<br>entry_SYSCALL_64_after_hwframe+0x6e/0xd8</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-52637</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30572</p>
</td>
<td rowspan="1" colspan="1">
<p>Netgear R6850 1.1.0.88 was discovered to contain a command injection vulnerability
via the ntp_server parameter.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30572</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30571</p>
</td>
<td rowspan="1" colspan="1">
<p>An information leak in the BRS_top.html component of Netgear R6850 v1.1.0.88
allows attackers to obtain sensitive information without any authentication
required.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30571</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30570</p>
</td>
<td rowspan="1" colspan="1">
<p>An information leak in debuginfo.htm of Netgear R6850 v1.1.0.88 allows
attackers to obtain sensitive information without any authentication required.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30570</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30569</p>
</td>
<td rowspan="1" colspan="1">
<p>An information leak in currentsetting.htm of Netgear R6850 v1.1.0.88 allows
attackers to obtain sensitive information without any authentication required.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30569</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30568</p>
</td>
<td rowspan="1" colspan="1">
<p>Netgear R6850 1.1.0.88 was discovered to contain a command injection vulnerability
via the c4-IPAddr parameter.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30568</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29477</p>
</td>
<td rowspan="1" colspan="1">
<p>Lack of sanitization during Installation Process in Dolibarr ERP CRM up
to version 19.0.0 allows an attacker with adjacent access to the network
to execute arbitrary code via a specifically crafted input.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29477</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-29734</p>
</td>
<td rowspan="1" colspan="1">
<p>Uncontrolled search path element issue exists in SonicDICOM Media Viewer
2.3.2 and earlier, which may lead to insecurely loading Dynamic Link Libraries.
As a result, arbitrary code may be executed with the privileges of the
running application.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-29734</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28589</p>
</td>
<td rowspan="1" colspan="1">
<p>An issue was discovered in Axigen Mail Server for Windows versions 10.5.18
and before, allows local low-privileged attackers to execute arbitrary
code and escalate privileges via insecure DLL loading from a world-writable
directory during service initialization.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28589</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-35764</p>
</td>
<td rowspan="1" colspan="1">
<p>Insufficient verification of data authenticity issue in Survey Maker prior
to 3.6.4 allows a remote unauthenticated attacker to spoof an IP address
when posting.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-35764</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2023-34423</p>
</td>
<td rowspan="1" colspan="1">
<p>Survey Maker prior to 3.6.4 contains a stored cross-site scripting vulnerability.
If this vulnerability is exploited, an arbitrary script may be executed
on the web browser of the user who is logging in to the website using the
product with the administrative privilege.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2023-34423</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28515</p>
</td>
<td rowspan="1" colspan="1">
<p>Buffer Overflow vulnerability in CSAPP_Lab CSAPP Lab3 15-213 Fall 20xx
allows a remote attacker to execute arbitrary code via the lab3 of csapp,lab3/
<a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">buflab-update.pl</a>component.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28515</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-24506</p>
</td>
<td rowspan="1" colspan="1">
<p>Cross Site Scripting (XSS) vulnerability in Lime Survey Community Edition
Version v.5.3.32+220817, allows remote attackers to execute arbitrary code
via the Administrator email address parameter in the General Setting function.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-24506</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31008</p>
</td>
<td rowspan="1" colspan="1">
<p>An issue was discovered in WUZHICMS version 4.1.0, allows an attacker
to execute arbitrary code and obtain sensitive information via the index.php
file.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31008</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30998</p>
</td>
<td rowspan="1" colspan="1">
<p>SQL Injection vulnerability in PHPGurukul Men Salon Management System
v.2.0, allows remote attackers to execute arbitrary code and obtain sensitive
information via the email parameter in the index.php component.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30998</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2021-27312</p>
</td>
<td rowspan="1" colspan="1">
<p>Server Side Request Forgery (SSRF) vulnerability in Gleez Cms 1.2.0, allows
remote attackers to execute arbitrary code and obtain sensitive information
via modules/gleez/classes/request.php.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2021-27312</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31011</p>
</td>
<td rowspan="1" colspan="1">
<p>Arbitrary file write vulnerability in beescms v.4.0, allows a remote attacker
to execute arbitrary code via a file path that was not isolated and the
suffix was not verified in admin_template.php.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31011</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-2322</p>
</td>
<td rowspan="1" colspan="1">
<p>The WooCommerce Cart Abandonment Recovery WordPress plugin before 1.2.27
does not have CSRF check in its bulk actions, which could allow attackers
to make logged in admins delete arbitrary email templates as well as delete
and unsubscribe users from abandoned orders via CSRF attacks.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-2322</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31013</p>
</td>
<td rowspan="1" colspan="1">
<p>Cross Site Scripting (XSS) vulnerability in emlog version Pro 2.3, allow
remote attackers to execute arbitrary code via a crafted payload to the
bottom of the homepage in footer_info parameter.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31013</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31012</p>
</td>
<td rowspan="1" colspan="1">
<p>An issue was discovered in SEMCMS v.4.8, allows remote attackers to execute
arbitrary code, escalate privileges, and obtain sensitive information via
the upload.php file.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31012</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31010</p>
</td>
<td rowspan="1" colspan="1">
<p>SQL injection vulnerability in SEMCMS v.4.8, allows a remote attacker
to obtain sensitive information via the ID parameter in Banner.php.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31010</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-31009</p>
</td>
<td rowspan="1" colspan="1">
<p>SQL injection vulnerability in SEMCMS v.4.8, allows a remote attacker
to obtain sensitive information via lgid parameter in Banner.php.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-31009</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-30166</p>
</td>
<td rowspan="1" colspan="1">
<p>In Mbed TLS 3.3.0 through 3.5.2 before 3.6.0, a malicious client can cause
information disclosure or a denial of service because of a stack buffer
over-read (of less than 256 bytes) in a TLS 1.3 server via a TLS 3.1 ClientHello.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-30166</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28836</p>
</td>
<td rowspan="1" colspan="1">
<p>An issue was discovered in Mbed TLS 3.5.x before 3.6.0. When negotiating
the TLS version on the server side, it can fall back to the TLS 1.2 implementation
of the protocol if it is disabled. If the TLS 1.2 implementation was disabled
at build time, a TLS 1.2 client could put a TLS 1.3-only server into an
infinite loop processing a TLS 1.2 ClientHello, resulting in a denial of
service. If the TLS 1.2 implementation was disabled at runtime, a TLS 1.2
client can successfully establish a TLS 1.2 connection with the server.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28836</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-28755</p>
</td>
<td rowspan="1" colspan="1">
<p>An issue was discovered in Mbed TLS 3.5.x before 3.6.0. When an SSL context
was reset with the mbedtls_ssl_session_reset() API, the maximum TLS version
to be negotiated was not restored to the configured one. An attacker was
able to prevent an Mbed TLS server from establishing any TLS 1.3 connection,
potentially resulting in a Denial of Service or forced version downgrade
from TLS 1.3 to TLS 1.2.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-28755</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-26495</p>
</td>
<td rowspan="1" colspan="1">
<p>Cross Site Scripting (XSS) vulnerability in Friendica versions after v.2023.12,
allows a remote attacker to execute arbitrary code and obtain sensitive
information via the BBCode tags in the post content and post comments function.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-26495</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-25864</p>
</td>
<td rowspan="1" colspan="1">
<p>Server Side Request Forgery (SSRF) vulnerability in Friendica versions
after v.2023.12, allows a remote attacker to execute arbitrary code and
obtain sensitive information via the fpostit.php component.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-25864</a></strong>
</p>
</td>
</tr>
<tr>
<td rowspan="1" colspan="1">
<p>CVE-2024-24724</p>
</td>
<td rowspan="1" colspan="1">
<p>Gibbon through 26.0.00 allows /modules/School%20Admin/messengerSettings.php
Server Side Template Injection leading to Remote Code Execution because
input is passed to the Twig template engine (messengerSettings.php) without
sanitization.</p>
</td>
<td rowspan="1" colspan="1">
<p>–</p>
</td>
<td rowspan="1" colspan="1">
<p><strong><a href="https://nvd.nist.gov/" rel="noopener noreferrer nofollow" target="_blank">https://nvd.nist.gov/vuln/detail/CVE-2024-24724</a></strong>
</p>
</td>
</tr>
</tbody>
</table>
<p></p>
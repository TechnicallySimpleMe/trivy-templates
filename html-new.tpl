<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{- escapeXML ( index . 0 ).Target }} - Trivy Report - {{ now }}</title>
  <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap" rel="stylesheet">
  <style>
    body {
      font-family: 'Roboto', sans-serif;
      background: #f0f2f5;
      margin: 0;
      padding: 0;
      text-align: center;
      color: #333;
    }
    header {
      background: #4CAF50;
      color: white;
      padding: 20px 0;
      box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
      margin-bottom: 20px;
    }
    header h1 {
      margin: 0;
    }
    table {
      width: 90%;
      margin: 0 auto 20px;
      border-collapse: collapse;
      box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
      background: white;
      overflow: hidden;
    }
    th, td {
      padding: 12px;
      border-bottom: 1px solid #ddd;
      text-align: left;
    }
    th {
      background: #f7f7f7;
      font-weight: bold;
    }
    tr:nth-child(even) {
      background: #f9f9f9;
    }
    tr:hover {
      background: #f1f1f1;
    }
    .severity {
      text-align: center;
      font-weight: bold;
      color: #fafafa;
      padding: 8px;
      border-radius: 4px;
    }
    .severity-LOW .severity { background-color: #5fbb31; }
    .severity-MEDIUM .severity { background-color: #e9c600; }
    .severity-HIGH .severity { background-color: #ff8800; }
    .severity-CRITICAL .severity { background-color: #e40000; }
    .severity-UNKNOWN .severity { background-color: #747474; }
    .links a, .links[data-more-links=on] a {
      display: block;
      color: #4CAF50;
      text-decoration: none;
      padding: 4px 0;
    }
    .links a:hover {
      text-decoration: underline;
    }
    .links[data-more-links=off] a:nth-of-type(1n+5) {
      display: none;
    }
    a.toggle-more-links {
      cursor: pointer;
      color: #4CAF50;
      text-decoration: none;
    }
    a.toggle-more-links:hover {
      text-decoration: underline;
    }
  </style>
  <script>
    window.onload = function() {
      document.querySelectorAll('td.links').forEach(function(linkCell) {
        var links = [].concat.apply([], linkCell.querySelectorAll('a'));
        links.sort(function(a, b) { return a.href > b.href ? 1 : -1; });
        links.forEach(function(link, idx) {
          if (links.length > 3 && idx === 3) {
            var toggleLink = document.createElement('a');
            toggleLink.innerText = "Show more links";
            toggleLink.href = "#toggleMore";
            toggleLink.className = "toggle-more-links";
            linkCell.appendChild(toggleLink);
          }
          linkCell.appendChild(link);
        });
      });
      document.querySelectorAll('a.toggle-more-links').forEach(function(toggleLink) {
        toggleLink.onclick = function() {
          var expanded = toggleLink.parentElement.getAttribute("data-more-links");
          toggleLink.parentElement.setAttribute("data-more-links", expanded === "on" ? "off" : "on");
          toggleLink.innerText = expanded === "on" ? "Show more links" : "Show fewer links";
          return false;
        };
      });
    };
  </script>
</head>
<body>
  <header>
    <h1>{{- escapeXML ( index . 0 ).Target }} - Trivy Report - {{ now }}</h1>
  </header>
  <table>
    {{- range . }}
    <tr class="group-header">
      <th colspan="6">{{ .Type | toString | escapeXML }}</th>
    </tr>
    {{- if (eq (len .Vulnerabilities) 0) }}
    <tr>
      <th colspan="6">No Vulnerabilities found</th>
    </tr>
    {{- else }}
    <tr class="sub-header">
      <th>Package</th>
      <th>Vulnerability ID</th>
      <th>Severity</th>
      <th>Installed Version</th>
      <th>Fixed Version</th>
      <th>Links</th>
    </tr>
    {{- range .Vulnerabilities }}
    <tr class="severity-{{ escapeXML .Vulnerability.Severity }}">
      <td class="pkg-name">{{ escapeXML .PkgName }}</td>
      <td>{{ escapeXML .VulnerabilityID }}</td>
      <td class="severity">{{ escapeXML .Vulnerability.Severity }}</td>
      <td class="pkg-version">{{ escapeXML .InstalledVersion }}</td>
      <td>{{ escapeXML .FixedVersion }}</td>
      <td class="links" data-more-links="off">
        {{- range .Vulnerability.References }}
        <a href={{ escapeXML . | printf "%q" }}>{{ escapeXML . }}</a>
        {{- end }}
      </td>
    </tr>
    {{- end }}
    {{- end }}
    {{- if (eq (len .Misconfigurations) 0) }}
    <tr>
      <th colspan="6">No Misconfigurations found</th>
    </tr>
    {{- else }}
    <tr class="sub-header">
      <th>Type</th>
      <th>Misconf ID</th>
      <th>Check</th>
      <th>Severity</th>
      <th>Message</th>
    </tr>
    {{- range .Misconfigurations }}
    <tr class="severity-{{ escapeXML .Severity }}">
      <td class="misconf-type">{{ escapeXML .Type }}</td>
      <td>{{ escapeXML .ID }}</td>
      <td class="misconf-check">{{ escapeXML .Title }}</td>
      <td class="severity">{{ escapeXML .Severity }}</td>
      <td style="white-space:normal;">
        {{ escapeXML .Message }}<br>
        <a href={{ escapeXML .PrimaryURL | printf "%q" }}>{{ escapeXML .PrimaryURL }}</

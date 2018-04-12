
<%
	String url = (String) request.getAttribute("URL");
	String app = (String) request.getAttribute("app");
%>

<html>
<head>
<link href="/css/style.css" rel="stylesheet" type="text/css">
</head>
<body>

	<h1>Whoops!</h1>

	It doesn't look like you've configured SAML IdP quite yet....please
	follow these steps:

	<ol>

		<h2>
			<li>Go to your IdP extract metadata.xml</li>
		</h2>


		<h2>
			<li>copy it at webinf/ folder of this application</li>
		</h2>
</body>
</html>
package com.samltestapp.saml;

import org.apache.commons.codec.binary.Base64;
import org.json.JSONObject;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import com.samltestapp.util.Bag;
import com.samltestapp.util.XSDDateTime;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Scanner;
import java.util.Set;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

public class SAMLServlet extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = -6922299528488813094L;
	private static final String SAML_REQUEST = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" AssertionConsumerServiceURL=\"{0}\" Destination=\"{1}\" ID=\"_{2}\" IssueInstant=\"{3}\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Version=\"2.0\"><saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">{4}</saml:Issuer></samlp:AuthnRequest>";
	private Boolean INITIALIZED = false;
	private String ISSUER = null;
	private String IDP_URL = null;
	private PublicKey IDP_PUBLIC_KEY = null;

	private String email = null;

	@Override
	public void init() throws ServletException {
		Scanner scanner;
		String samlMetadata = null;

		System.out.println("initiating login here Hsharma");
		try {
			scanner = new Scanner(new File("src/main/webapp/WEB-INF/IDCSMetadata.xml"));

			samlMetadata = scanner.useDelimiter("\\A").next();
			scanner.close();
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		}

		if (samlMetadata != null) {

			Document metadataDocument = null;

			try {

				DocumentBuilderFactory domFactory = DocumentBuilderFactory.newInstance();
				domFactory.setNamespaceAware(true);
				DocumentBuilder builder = null;
				builder = domFactory.newDocumentBuilder();
				metadataDocument = builder
						.parse(new InputSource(new ByteArrayInputStream(samlMetadata.getBytes("UTF-8"))));

			} catch (Exception e) {
				throw new ServletException("Error decoding SAML Metadata", e);
			}

			NamespaceContext namespaceContext = new SAMLNamespaceResolver();
			XPathFactory factory = XPathFactory.newInstance();
			XPath xpath = factory.newXPath();
			xpath.setNamespaceContext(namespaceContext);

			try {

				XPathExpression edXPath = xpath.compile("/md:EntityDescriptor");
				NodeList edXPathResult = (NodeList) edXPath.evaluate(metadataDocument, XPathConstants.NODESET);
				if (edXPathResult.getLength() != 1)
					throw new ServletException("No EntityDescriptor in SAML_METADATA");
				Node edNode = edXPathResult.item(0);
				ISSUER = edNode.getAttributes().getNamedItem("entityID").getTextContent();
				if (ISSUER == null)
					throw new ServletException("No entityID on Entity Descriptor in SAML_METADATA");

				XPathExpression certXPath = xpath.compile(
						"/md:EntityDescriptor/md:IDPSSODescriptor/md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate");
				StringBuffer encodedCert = new StringBuffer("-----BEGIN CERTIFICATE-----\n");

				encodedCert.append(
						"MIIDXzCCAkegAwIBAgIGAWFO2ktsMA0GCSqGSIb3DQEBCwUAMFcxEzARBgoJkiaJ k/IsZAEZFgNjb20xFjAUBgoJkiaJk/IsZAEZFgZvcmFjbGUxFTATBgoJkiaJk/Is ZAEZFgVjbG91ZDERMA8GA1UEAxMIQ2xvdWQ5Q0EwHhcNMTgwMjAxMDA1MzA0WhcN MjgwMjAxMDA1MzA0WjBWMRMwEQYDVQQDEwpzc2xEb21haW5zMQ8wDQYDVQQDEwZD bG91ZDkxLjAsBgNVBAMTJWlkY3MtYTcxMjgzYzUyYWI1NGU4MTk3YTM3ZDEwY2U0 MTU4OTAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCX63qL22k4hLZP kwm8mX/z4hf5H+TJU1xn4eZZCxl2bVsv+/oeOJ9jZGRPBypAfhw0subcrWEUY/DG tP2k6FVhWziKI0+IKtyDiqdKWTL9GHeTgv72UyWH8bLGldew7i/roUSAief1SuG0 rRKzZvGRvSilt2WoSbIILqbNF4trelmVnH0OF7sZ7P6xiapr0UFItypGViVmgOJm UmydYFe8q85h2aEEyxfrsoEE6EOcADG2sbmkvV9kAILns66vKoZCJpKApR0uDOyT 6Fc7AkE+WPtqltYNHOEVacH9fvpl+0rhJjFqPmhdIYl4PojffIjQiY6DOQvMGkAQ +9MObVOvAgMBAAGjMjAwMB0GA1UdDgQWBBSzOfzruaMvkz5zo4HIc4ts9DkYfzAP BgNVHQ8BAf8EBQMDB9gAMA0GCSqGSIb3DQEBCwUAA4IBAQA7nlM2+JDa6Ead7peX 2HuOUgxiYYMathjjx9gG/GBH2ZbDCoNniofgbYf3joBPw4sE2Gml9rcVYZETaBCX NqY346kQILpkKsFYO9bKzOM4rzms2WQJ9K0ZDjSClhqTqtxPhN4gSv9BFXpCqHtL tnX0prD79a70Lv+3qCP3goEa5H/EPNCNQ6cfoLQtLz4v82N/pCYkupmBVPJ8J+yg l6lblyh4LOy3QWFRXZlQkuCMko43ZWZ5XOywmLO6cVT+It17unbylPG/p3h9YGBi Ek6xJzmpXj4onsVLQ53tzhV5Tb5W2LY3Etytw5x9jICvxVD51gHmwUBZSqIpFIAe 0a12");
				encodedCert.append("\n-----END CERTIFICATE-----\n");
				try {
					CertificateFactory cf = CertificateFactory.getInstance("X.509");
					Certificate certificate = cf
							.generateCertificate(new ByteArrayInputStream(encodedCert.toString().getBytes("UTF-8")));
					IDP_PUBLIC_KEY = certificate.getPublicKey();
				} catch (CertificateException e) {
					throw new ServletException("Error getting PublicKey from Cert", e);
				} catch (UnsupportedEncodingException e) {
					throw new ServletException("Error getting PublicKey from Cert", e);
				}

				XPathExpression ssoXPath = xpath.compile(
						"//md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']");
				NodeList ssoXPathResult = (NodeList) ssoXPath.evaluate(metadataDocument, XPathConstants.NODESET);
				if (ssoXPathResult.getLength() != 1)
					throw new ServletException("No SingleSignOnService with Redirect Binding");
				Node ssoNode = ssoXPathResult.item(0);
				IDP_URL = ssoNode.getAttributes().getNamedItem("Location").getTextContent();
				if (IDP_URL == null)
					throw new ServletException("No Location for SingleSignOnService with Redirect Binding");

			} catch (XPathExpressionException e) {
				throw new ServletException("Error Executing XPaths on Metadata", e);
			}

			System.out.println("Initialized SAML with:");
			System.out.println("ISSUER:" + ISSUER);
			System.out.println("IDP_URL:" + IDP_URL);
			System.out.println("IDP_PUBLIC_KEY:" + IDP_PUBLIC_KEY);
			INITIALIZED = true;
			System.out.println("loaded config ....");

		} else {
			System.out.println("SAML isn't yet initialized!");
		}

	}

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		if (request.getCookies() != null) {
			for (Cookie cookie : request.getCookies()) {
				cookie.setValue("");
				cookie.setMaxAge(0);
				cookie.setPath("/");

				response.addCookie(cookie);
			}
		}
		String logout = request.getParameter("logout");
		if (logout != null) {
			response.sendRedirect("/");
			return;

		}

		String url = request.getRequestURL().toString();
		// herokuism
		url = url.replaceFirst("http", "https");
		String app = null;
		try {
			app = new URI(url).getHost().split("\\.")[0];
		} catch (URISyntaxException e) {
			throw new ServletException(e);
		}
		if (!INITIALIZED) {
			request.setAttribute("URL", url);
			request.setAttribute("app", app);
			RequestDispatcher dispatcher = getServletContext().getRequestDispatcher("/configure.jsp");
			dispatcher.forward(request, response);
			return;

		} else {

			String[] args = new String[5];
			args[0] = url;
			args[1] = IDP_URL;
			args[2] = UUID.randomUUID().toString();
			args[3] = new XSDDateTime().getDateTime();
			args[4] = url;
			MessageFormat html;
			html = new MessageFormat(SAML_REQUEST);
			String requestXml = html.format(args);
			byte[] input = requestXml.getBytes("UTF-8");

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			Deflater d = new Deflater(Deflater.DEFLATED, true);
			DeflaterOutputStream dout = new DeflaterOutputStream(baos, d);
			dout.write(input);
			dout.close();

			String encodedRequest = Base64.encodeBase64String(baos.toByteArray());

			String SAMLRequest = URLEncoder.encode(encodedRequest, "UTF-8");

			String relayState = request.getParameter("RelayState");
			String redirect = null;
			redirect = IDP_URL + "?SAMLRequest=" + SAMLRequest;

			if (relayState != null)
				redirect += "&RelayState=" + relayState;
			response.sendRedirect(redirect);

		}

	}

	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		System.out.println("validating incoming SAML assertion ....");

		String url = request.getRequestURL().toString();
		url = url.replaceFirst("http", "https");
		String encodedResponse = request.getParameter("SAMLResponse");
		System.out.println(encodedResponse);
		String relayState = request.getParameter("RelayState");
		if ((relayState == null) || (relayState.equals("")))
			relayState = "/";

		SAMLValidator sv = new SAMLValidator();
		try {
			Identity identity = sv.validate(encodedResponse, IDP_PUBLIC_KEY, null, ISSUER, url, url);

			JSONObject identityJSON = new JSONObject();
			identityJSON.put("subject", identity.getSubject());
			Bag attributes = identity.getAttributes();
			Set keySet = attributes.keySet();
			Iterator iterator = keySet.iterator();
			System.out.println(identity.getSubject());
			System.out.println("printed subject ....");
			while (iterator.hasNext()) {
				String key = (String) iterator.next();
				identityJSON.put(key, (ArrayList<String>) attributes.getValues(key));
			}
			Cookie identityCookie = new Cookie("IDENTITY",
					Base64.encodeBase64URLSafeString(identityJSON.toString().getBytes("UTF-8")));
			// cutom code
			this.email = identity.getSubject();
			if (identity.getSubject().equals("sharma.himanshu@pwc.com")) {
				response.setContentType("text/html");
				PrintWriter out;
				out = response.getWriter();
				out.println("<body style=\"background-color:Tomato\">");

				out.println("<h1>" + "You dont have access. " + "</h1>");
				out.println("	<br>You have access </br> <br> <a href=\"/_saml?logout=true\"\n"
						+ "			class=\"button center\">Logout</a>");
				out.println("<br>");

				request.getSession().invalidate();

			} else {
				response.addCookie(identityCookie);
				response.sendRedirect(relayState);
			}
		} catch (Exception e) {
			e.printStackTrace();
			response.sendError(401, "Access Denied: " + e.getMessage());
			return;
		}

	}

}

/**
 * 
 */
package com.samltestapp.saml;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.text.MessageFormat;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;

import com.samltestapp.util.XSDDateTime;

/**
 * @author hsharma015
 *
 */
public class LogoutServlet extends HttpServlet {
	private static final String SAML_REQUEST = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" AssertionConsumerServiceURL=\"{0}\" Destination=\"{1}\" ID=\"_{2}\" IssueInstant=\"{3}\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Version=\"2.0\"><saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">{4}</saml:Issuer></samlp:AuthnRequest>";

	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		doPost(request, response);

	}

	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		System.out.println("logout servlet called .......");
		String slo = "https://idcs-a71283c52ab52ab54e8197a37d10ce415890.identity.oraclecloud.com/fed/v1/sp/slo";
		Cookie cookie = new Cookie("IDENTITY", "");
		cookie.setMaxAge(0);
		response.addCookie(cookie);
		response.sendRedirect("/");

		String url = request.getRequestURL().toString();
		url = url.replaceFirst("http", "https");
		String app = null;
		try {
			app = new URI(url).getHost().split("\\.")[0];
		} catch (URISyntaxException e) {
			throw new ServletException(e);
		}

		String[] args = new String[5];
		args[0] = url;
		args[1] = slo;
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
		String redirect = slo + "?SAMLRequest=" + SAMLRequest;
		if (relayState != null)
			redirect += "&RelayState=" + relayState;
		response.sendRedirect(redirect);

	}

}

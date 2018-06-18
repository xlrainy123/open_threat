package utils;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import okhttp3.OkHttpClient;

public class HttpUtils {
	
	public static OkHttpClient getHttpClient(boolean isHttps) throws KeyManagementException, NoSuchAlgorithmException {
		if (isHttps) 
			return getHttps().build();
		return getHttp();
	}
	public static OkHttpClient getHttpClient() {
		return getHttp();
	}
	private static OkHttpClient getHttp() {
		OkHttpClient client = new OkHttpClient();
		return client;
	}
	
	public static OkHttpClient.Builder getHttps() throws NoSuchAlgorithmException, KeyManagementException {
		final TrustManager[] trustAllCerts = new TrustManager[] {
				new X509TrustManager() {
					@Override
					public X509Certificate[] getAcceptedIssuers() {
						return new java.security.cert.X509Certificate[]{};
					}
					@Override
					public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {}
					@Override
					public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {}
				}
		};
		final SSLContext sslContext = SSLContext.getInstance("SSL");
		sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
		final javax.net.ssl.SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
		OkHttpClient.Builder builder = new OkHttpClient.Builder();
		builder.sslSocketFactory(sslSocketFactory);
		builder.hostnameVerifier(new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        });
		return builder;
//		return builder.build();
	}
}	
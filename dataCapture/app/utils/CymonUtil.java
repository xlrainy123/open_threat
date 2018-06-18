package utils;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import net.sf.json.JSONObject;
import okhttp3.Call;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class CymonUtil {
	private static final String authorization = "Bearer 00bd61a12044a62d5a88ff5ed4643e392a99bbd1";
	private static final String contentType = "application/json";
	// private static final String ip_report =
	// "https://api.cymon.io/v2/ioc/search/ip/%s?proxies=%s";
	private static final String ip_report_event = "https://cymon.io:443/api/nexus/v1/ip/%s/events/"; // v1
	private static final String ip_report_domain = "https://cymon.io:443/api/nexus/v1/ip/%s/domains/"; // v1
	private static final String ip_report_url = "https://cymon.io:443/api/nexus/v1/ip/%s/urls/"; // v1
	private static final String ip_report_malware = "https://cymon.io:443/api/nexus/v1/ip/%s/malware/"; // v1
	private static final String proxy_url = "http://pvt.daxiangdaili.com/ip/?tid=555761654329388&num=1&protocol=https&filter=on";
	// private static String proxy = "https://112.86.104.13:8888";
	private String proxy_host = "112.86.104.13";
	private int proxy_port = 8888;

	public void updateProxy() throws IOException {
		OkHttpClient client = new OkHttpClient();
		// new OkHttpClient().newBuilder().proxy(new Proxy(type, sa))
		Request request = new Request.Builder().url(proxy_url).build();
		Call call = client.newCall(request);
		Response response = call.execute();
		String proxy = response.body().string();
		String[] host_port = proxy.split(":");
		String proxy_host = (String) host_port[0];
		int proxy_port = Integer.parseInt(host_port[1]);
	}

	public JSONObject getIpReportWithMalware(String ip) {
		if (!isIp(ip)) {
			return JSONObject.fromObject(String.valueOf("not ip"));
		}
		// OkHttpClient client = null;
		Response response = null;
		OkHttpClient.Builder builder = null;
		String all = "{}";
		try {
			// client = HttpUtils.getHttpClient(true);
			builder = HttpUtils.getHttps();
		} catch (Exception e) {
			e.printStackTrace();
		}

		String url = String.format(ip_report_event, ip);
		System.out.println(url);
		for (;;) {
			Request request = new Request.Builder().url(String.format(ip_report_malware, ip))
					.header("Authorization", authorization).header("Content_Type", contentType).build();
			builder.proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxy_host, proxy_port)));
			OkHttpClient client = builder.build();
			Call call = client.newCall(request);
			try {
				response = call.execute();
				all = response.body().string();
			} catch (IOException e) {
				e.printStackTrace();
			}
			if (all.contains("seconds")) {
				try {
					updateProxy();
					try {
						Thread.currentThread().sleep(1000);
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
				} catch (IOException e) {
					e.printStackTrace();
				}
			} else {
				break;
			}
		}
		JSONObject allJson = JSONObject.fromObject(all);
		// System.out.println(all);
		return allJson;
	}

	private boolean isIp(String ip) {
		return true;
	}

	public JSONObject getIpReportWithDomain(String ip) {
		if (!isIp(ip)) {
			return JSONObject.fromObject(String.valueOf("not ip"));
		}
		// OkHttpClient client = null;
		OkHttpClient.Builder builder = null;
		Response response = null;
		try {
			builder = HttpUtils.getHttps();
		} catch (KeyManagementException | NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}
		String all = "{'error':'1'}";
		String url = String.format(ip_report_event, ip);
		System.out.println(url);
		for (;;) {
			Request request = new Request.Builder().url(String.format(ip_report_domain, ip))
					.header("Authorization", authorization).header("Content_Type", contentType).build();
			builder.proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxy_host, proxy_port)));
			OkHttpClient client = builder.build();
			Call call = client.newCall(request);
			try {
				response = call.execute();
				all = response.body().string();
			} catch (IOException e) {
				e.printStackTrace();
			}
			if (all.contains("seconds")) {
				try {
					updateProxy();
					try {
						Thread.currentThread().sleep(1000);
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
				} catch (IOException e) {
					e.printStackTrace();
				}
			} else {
				break;
			}
		}
		JSONObject allJson = JSONObject.fromObject(all);
		// System.out.println(all);
		return allJson;
	}

	public JSONObject getIpReportWithEvent(String ip) {
		if (!isIp(ip)) {
			return JSONObject.fromObject(String.valueOf("not ip"));
		}
		// OkHttpClient client = null;
		Response response = null;
		OkHttpClient.Builder builder = null;
		String all = "{}";
		try {
			builder = HttpUtils.getHttps();
		} catch (Exception e) {
			e.printStackTrace();
		}
		String url = String.format(ip_report_event, ip);
		System.out.println(url);
		for (;;) {
			Request request = new Request.Builder().url(String.format(ip_report_event, ip))
					.header("Authorization", authorization).header("Content_Type", contentType).build();
			builder.proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxy_host, proxy_port)));
			OkHttpClient client = builder.build();
			Call call = client.newCall(request);
			try {
				response = call.execute();
				all = response.body().string();
			} catch (IOException e) {
				e.printStackTrace();
			}
			if (all.contains("seconds")) {
				try {
					updateProxy();
					try {
						Thread.currentThread().sleep(1000);
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
				} catch (IOException e) {
					e.printStackTrace();
				}
			} else {
				break;
			}
		}
		JSONObject allJson = JSONObject.fromObject(all);
		return allJson;
	}

	public JSONObject getIpReportWithUrl(String ip) {
		if (!isIp(ip)) {
			return JSONObject.fromObject(String.valueOf("not ip"));
		}
		// OkHttpClient client = null;
		OkHttpClient.Builder builder = null;
		Response response = null;
		try {
			builder = HttpUtils.getHttps();
		} catch (KeyManagementException e1) {
			e1.printStackTrace();
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}
		String all = "{}";
		String url = String.format(ip_report_url, ip);
		System.out.println(url);
		for (;;) {
			Request request = new Request.Builder().url(String.format(ip_report_url, ip))
					.header("Authorization", authorization).header("Content_Type", contentType).build();
			builder.proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxy_host, proxy_port)));
			OkHttpClient client = builder.build();
			Call call = client.newCall(request);
			try {
				response = call.execute();
				all = response.body().string();
			} catch (IOException e) {
				e.printStackTrace();
			}
			if (all.contains("seconds")) {
				try {
					updateProxy();
					try {
						Thread.currentThread().sleep(1000);
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
				} catch (IOException e) {
					e.printStackTrace();
				}
			} else {
				break;
			}
		}
		JSONObject allJson = JSONObject.fromObject(all);
		return allJson;
	}

}

package utils;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import models.Intelligent;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import okhttp3.Call;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import utils.Interface.Data;
import utils.Interface.IP;

public class IBMUtil {
	public static final String authorization = "Basic YjUzYzY0MzMtMWI4OC00Y2JiLWI0OGYtN2U1NzI"
			+ "0YmM3OGQ3OjliZTUwMTFlLTIxMWEtNGQ2My04MTE2LWVjMjk5N2NmMDFlYg==";
	public static final String accept = "application/json";
	public static final String ip_from_category = "https://api.xforce.ibmcloud.com/ipr?category=";
	public static final String ip_report = "https://api.xforce.ibmcloud.com/ipr/";
	public static final String ip_reputation = "https://api.xforce.ibmcloud.com/ipr/history/";
	public static final String malware_from_ip = "https://api.xforce.ibmcloud.com/ipr/malware/";
	public static final String resolve_content = "https://api.xforce.ibmcloud.com/resolve/"; // ¿ÉÒÔœâÎöip£¬dns»òurl

	public enum Catagory {
		spam("Spam"), malware("Malware"), Bots("Bots"), as("Anonymisation Services"), sip("Scanning IPs"), dip(
				"Dynamic IPs"), bcacs("Botnet Command and Control Server");
		public String name;

		private Catagory(String name) {
			this.name = name;
		}

		public static String getValue(String category) {
			for (Catagory catagory : Catagory.values()) {
				if (catagory.name().equals(category)) {
					return catagory.name;
				}
			}
			return null;
		}

	}
	
	public JSONObject getIpAccordingCategory(String category) {
		OkHttpClient client = null;
		String result = "";
		Response response = null;
		try {
			client = HttpUtils.getHttpClient(true);
		} catch (KeyManagementException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		String catagory = Catagory.getValue(category);
		String url = String.format(IBMUtil.ip_from_category + "%s", catagory);
		String auth = IBMUtil.authorization;
		String accept = IBMUtil.accept;
		Request request = new Request.Builder().url(url).header("Accept", accept).header("Authorization", auth).build();
		Call call = client.newCall(request);
		try {
			response = call.execute();
			result = response.body().string();
		} catch (IOException e) {
			e.printStackTrace();
		}
		JSONObject allJSON = JSONObject.fromObject(result);
		System.out.println(allJSON);
		return allJSON;
	}

	
	public JSONObject getIpReport(String ip) {
		if (!isIp(ip)) {
			return JSONObject.fromObject(String.valueOf("not ip"));
		}
		OkHttpClient client = null;
		Response response = null;
		String result = "{}";
		try {
			client = HttpUtils.getHttpClient(true);
		} catch (Exception e) {
			e.printStackTrace();
		}
		String url = String.format(ip_report + "%s", ip);
		String auth = IBMUtil.authorization;
		String accept = IBMUtil.accept;
		Request request = new Request.Builder().url(url).header("Accept", accept).header("Authorization", auth).build();
		Call call = client.newCall(request);
		try {
			response = call.execute();
			result = response.body().string();
			
		} catch (IOException e) {
			e.printStackTrace();
		}
		JSONObject allJSON = JSONObject.fromObject(result);
		return allJSON;
	}

	private boolean isIp(String ip) {
		return true;
	}

	
	public JSONObject getIpReputation(String ip) {
		if (!isIp(ip)) {
			return JSONObject.fromObject(String.valueOf("not ip"));
		}
		OkHttpClient client = null;
		Response response = null;
		String result = "";
		try {
			client = HttpUtils.getHttpClient(true);
		} catch (KeyManagementException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		String url = String.format(ip_reputation + "%s", ip);
		String auth = IBMUtil.authorization;
		String accept = IBMUtil.accept;
		Request request = new Request.Builder()
				.url(url)
				.header("Accept", accept)
				.header("Authorization", auth)
				.build();
		Call call = client.newCall(request);
		try {
			response = call.execute();
			result = response.body().string();
		} catch (IOException e) {
			e.printStackTrace();
		}
		JSONObject allJSON = JSONObject.fromObject(result);
//		System.out.println(allJSON);
		return allJSON;
	}

	
	public JSONObject getMalwareFromIp(String ip) {
		// "186.167.248.148"
		if (!isIp(ip)) {
			return JSONObject.fromObject(String.valueOf("not ip"));
		}
		OkHttpClient client = null;
		Response response = null;
		String result = "{}";
		try {
			client = HttpUtils.getHttpClient(true);
		} catch (KeyManagementException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		String url = String.format(malware_from_ip + "%s", ip);
		String auth = IBMUtil.authorization;
		String accept = IBMUtil.accept;
		Request request = new Request.Builder()
				.url(url)
				.header("Accept", accept)
				.header("Authorization", auth)
				.build();
		Call call = client.newCall(request);
		try {
			response = call.execute();
			result = response.body().string();
		} catch (IOException e) {
			e.printStackTrace();
		}
		JSONObject allJSON = JSONObject.fromObject(result);
//		System.out.println(allJSON);
		return allJSON;
	}

	
	public JSONObject resolveIpDnsUrl(String content) {
		OkHttpClient client = null;
		Response response = null;
		String result = "";
		try {
			client = HttpUtils.getHttpClient(true);
		} catch (KeyManagementException | NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		String url = String.format(resolve_content + "%s", content);
		String auth = IBMUtil.authorization;
		String accept = IBMUtil.accept;
		Request request = new Request.Builder()
				.url(url)
				.header("Accept", accept)
				.header("Authorization", auth)
				.build();
		Call call = client.newCall(request);
		try {
			response = call.execute();
			result = response.body().string();
		} catch (IOException e) {
			e.printStackTrace();
		}
		JSONObject allJSON = JSONObject.fromObject(result);
//		System.out.println(allJSON);
		return allJSON;
	}

	public JSONObject getUrlReport(String url) {
		return resolveIpDnsUrl(url);
	}
}
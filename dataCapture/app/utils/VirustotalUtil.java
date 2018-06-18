package utils;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import net.sf.json.JSONObject;
import okhttp3.Call;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class VirustotalUtil{
	
	private static final String ip_report = "https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=%s&ip=%s";
	private static final String apiKey = "5512e3e8ec7abbed6ff7a5991ea2343ff2be91f92b807a5c4816a95274f94ace";
	
	public JSONObject getIpReport(String ip){
		if (! isIp(ip)) {
			return JSONObject.fromObject(String.valueOf("not ip"));
		}
		OkHttpClient client = null;
		Response response = null;
	    try {
			client = HttpUtils.getHttpClient(true);
		} catch (KeyManagementException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		String url = String.format(ip_report, apiKey,ip);
		Request request = new Request.Builder()
				.url(url)
				.build();
		Call call = client.newCall(request);
	    try {
			response = call.execute();
			if (response.code() == 200) {
				String result = response.body().string();
				JSONObject allJSON = JSONObject.fromObject(result);
				return allJSON;
			}else {
				System.out.println(response.code());
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	private boolean isIp(String ip) {
		return true;
	}
}

package job;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import okhttp3.OkHttpClient;
import utils.VirustotalUtil;

public class IPHandlerWithVirustotal implements Runnable{
	public Set<Object> malware;
	public List<Object> urls ;
	public String ip;
	public OkHttpClient client = null;
	public boolean complete = false;
	private CountDownLatch count;
	
	public IPHandlerWithVirustotal() {}
	public IPHandlerWithVirustotal(CountDownLatch count,OkHttpClient client,
			Set<Object> malware, List<Object> urls) {
		this.count = count;
		this.client = client;
		this.malware = malware;
		this.urls = urls;
	}
	public void parserMalware(){
		JSONObject virusAll = new VirustotalUtil().getIpReport(ip);
		JSONArray detected_communicating_samples = null;
		JSONArray detected_downloaded_samples = null;
		JSONArray detected_referrer_samples = null;
		try {
			detected_communicating_samples = virusAll.getJSONArray("detected_communicating_samples");
		}catch (Exception e) {
			detected_communicating_samples = new JSONArray();
		}
		try {
			detected_downloaded_samples = virusAll.getJSONArray("detected_downloaded_samples");
		}catch (Exception e) {
			detected_downloaded_samples = new JSONArray();
		}
		try {
			detected_referrer_samples = virusAll.getJSONArray("detected_referrer_samples");
		}catch (Exception e) {
			detected_referrer_samples = new JSONArray();
		}
		if (!detected_communicating_samples.isEmpty()) {
			for (Object object : detected_communicating_samples) {
				String hash = "";
				try {
					hash = ((JSONObject)object).getString("sha256");
				}catch (Exception e) {
					hash = "";
				}
				if (!"".equals(hash)) {
					malware.add("'"+hash+"'");
				}
			}
		}
		if (!detected_downloaded_samples.isEmpty()) {
			for (Object object : detected_downloaded_samples) {
				String hash = "";
				try {
					hash = ((JSONObject)object).getString("sha256");
				}catch (Exception e) {
					hash = "";
				}
				if (!"".equals(hash)) {
					malware.add("'"+hash+"'");
				}
			}
		}
		if (!detected_referrer_samples.isEmpty()) {
			for (Object object : detected_referrer_samples) {
				String hash = "";
				try {
					hash = ((JSONObject)object).getString("sha256");
				}catch (Exception e) {
					hash = "";
				}
				if (!"".equals(hash)) {
					malware.add("'"+hash+"'");
				}
			}
		}
		System.out.println("-----------------Virustatol malware:"+malware.size());
	}
	public void parserUrl() {
		JSONObject virusAll = new VirustotalUtil().getIpReport(ip);
		JSONArray urlArray = null;
		try {
			urlArray = virusAll.getJSONArray("detected_urls");
		}catch (Exception e) {
			urlArray = new JSONArray();
		}
		if (!urlArray.isEmpty()) {
			for (Object object : urlArray) {
				String url = "";
				try {
					url = ((JSONObject)object).getString("url");
				}catch (Exception e) {
					url = "";
				}
				if (!"".equals(url)) {
					urls.add("'"+url+"'");
				}
			}
			System.out.println("-----------------Virustatol urls:"+urls.size());
		}
	}
	public void run() {
//		parserMalware();
//		parserUrl();
		complete = true;
		count.countDown();
	}
	
}

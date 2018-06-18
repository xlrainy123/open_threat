package job;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import okhttp3.OkHttpClient;
import utils.CymonNoProxy;
import utils.model.CymonIntell;
import utils.model.DetailUrl;
import utils.model.IntellegentInterface;


public class IPHandlerWithCymon implements Runnable{
	public List<IntellegentInterface> intelligents = new ArrayList<>();
	public List<Object> detailUrl = new ArrayList<>();
	public List<Object> urls = new ArrayList<>();
	public List<Object> domains = new ArrayList<>();
	public Set<Object> malware = new HashSet<>();
	public String ip;
	public OkHttpClient client = null;
	public boolean complete = false;
	private CountDownLatch count;
	
	public IPHandlerWithCymon() {}
	public IPHandlerWithCymon(CountDownLatch count, OkHttpClient client,
			List<IntellegentInterface> intelligents, List<Object> detailUrl, List<Object> urls,
			List<Object> domains, Set<Object> malware) {
		this.count = count;
		this.client = client;
		this.intelligents = intelligents;
		this.detailUrl = detailUrl;
		this.urls = urls;
		this.domains = domains;
		this.malware = malware;
	}
 	public void parserEvent() {
		JSONObject cyAll = new CymonNoProxy().getIpReportWithEvent(ip);
		JSONArray cyArray = null;
		try {
			cyArray = cyAll.getJSONArray("results");
		}catch (Exception e) {
			cyArray = new JSONArray();
		}
		if (!cyArray.isEmpty()) {
			for (Object object : cyArray) {
//				created tag title source
				String time = ""; 
				String description = "";
				String tag = "";
				String detail = "";
				String update = "";
				try {
					time = ((JSONObject)object).getString("created");
				}catch (Exception e) {
					time = "";
				}
				try {
					description = ((JSONObject)object).getString("title");
				}catch (Exception e) {
					description = "";
				}
				try {
					tag = ((JSONObject)object).getString("tag");
				}catch (Exception e) {
					tag = "";
				}
				try {
					detail = ((JSONObject)object).getString("details_url");
				}catch (Exception e) {
					detail = "";
				}
				try {
					update = ((JSONObject)object).getString("updated");
				}catch (Exception e) {
					update = "";
				}
				CymonIntell cymonIntell = new CymonIntell();
				DetailUrl deurl = new DetailUrl();
				deurl.event_url = (detail == null || "null".equals(detail))
									? "" : detail;
				deurl.time = update;
				cymonIntell.source = retriveSource(description);
				cymonIntell.description = description;
				cymonIntell.tag = tag;
				cymonIntell.time = time;
				if (!deurl.event_url.equals("")) {
					detailUrl.add(deurl);
				}
				intelligents.add(cymonIntell);
			}
			System.out.println("-----------------cymon intelligents:"+intelligents.size());
			System.out.println("-----------------cymon detailUrl:"+detailUrl.size());
		}
	}
 	public String retriveSource(String description) {
 		if (!"".equals(description)) {
 			String[] strings = description.trim().split("by");
 			return strings[1].trim();
 		}
		return "open cymon";
 	}
	public void parserUrl() {
		JSONObject urlAll = new CymonNoProxy().getIpReportWithUrl(ip);
		JSONArray urlArray = null;
		try {
			urlArray = urlAll.getJSONArray("results");
		}catch (Exception e) {
			urlArray = new JSONArray();
		}
		if (!urlArray.isEmpty()) {
			for (Object object : urlArray) {
				String url = "";
				String time = "";
				try {
					url = ((JSONObject)object).getString("location");
				}catch (Exception e) {
					url = "";
				}
				try {
					time = ((JSONObject)object).getString("created");
				} catch (Exception e) {
					time = "";
				}
				if (!"".equals(url)) {
					urls.add("{"+"'url':"+"'"+url+"'"+","+"'time':"+"'"+time+"'"+"}");
				}
			}
			System.out.println("-----------------cymon urls:"+urls.size());
		}
	}
	
	public void parserDomain() {
		JSONObject domianAll = new CymonNoProxy().getIpReportWithDomain(ip);
		JSONArray domianArray = null;
		try {
			domianArray = domianAll.getJSONArray("results");
		}catch (Exception e) {
			domianArray = new JSONArray();
		}
		if (!domianArray.isEmpty()) {
			for (Object object : domianArray) {
				String domain = "";
				try {
					domain = ((JSONObject)object).getString("name");
				}catch (Exception e) {
					domain = "";
				}
				if (!"".equals(domain)) {
					domains.add("'"+domain+"'");
				}
			}
			System.out.println("-----------------cymon domains:"+domains.size());
		}
	}

	public void parserMalware(){
//		JSONObject malwareAll = new Cymon().getIpReportWithMalware(ip);
		JSONObject malwareAll = new CymonNoProxy().getIpReportWithMalware(ip);
		JSONArray malwareArray = null;
		try {
			malwareArray = malwareAll.getJSONArray("results");
		}catch (Exception e) {
			malwareArray = new JSONArray();
		}
		if (!malwareArray.isEmpty()) {
			for (Object object : malwareArray) {
				String hash = "";
				try {
					hash = ((JSONObject)object).getString("hash_value");
				}catch (Exception e) {
					hash = "";
				}
				if (!"".equals(hash)) {
					malware.add("'"+hash+"'");
				}
			}
		}
		System.out.println("-----------------cymon malware:"+malware.size());
	}

	public void run() {
		parserEvent();
		parserUrl();
		parserDomain();
		parserMalware();
		complete = true;
		count.countDown();
	}
	
}

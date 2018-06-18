package utils.dataHandler;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import models.IP;
import models.SearchIp;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import utils.CymonUtil;
import utils.IBMUtil;
import utils.factory.DataFactory;
import utils.model.CymonIntell;
import utils.model.DetailUrl;
import utils.model.IBMIntell;

public class IBMHandler {
	
	public static void ibmIpHandlerWithMalware(String ip, Set<Object> malware) {
		JSONObject malwareAll = new IBMUtil().getMalwareFromIp(ip);
		JSONArray malwareArray = null;
		try {
			malwareArray = malwareAll.getJSONArray("malware");
		}catch (Exception e) {
			malwareArray = new JSONArray();
		}
		for (Object object : malwareArray) {
			String md5 = "";
			try {
				md5 = ((JSONObject)object).getString("md5");
			}catch (Exception e) {
				md5 = "";
			}
			if (!"".equals(md5)) {
				malware.add(md5);
			}
		}
//		System.out.println(malware);
	}
	
	public static void cymonIpHandlerWithMalware(String ip, Set<Object> malware) {
		JSONObject malwareAll = new CymonUtil().getIpReportWithMalware(ip);
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
					malware.add(hash);
				}
			}
		}
//		System.out.println(malware);
	}
	
	public static void virustotalIpHandlerWithMalware(String ip, Set<Object> malware) {
		JSONObject virusAll = DataFactory.getVirustatolInstance().getIpReport(ip);
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
					malware.add(hash);
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
					malware.add(hash);
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
					malware.add(hash);
				}
			}
		}
//		System.out.println(malware);
	}
	//ok
	public static void virustotalIpHandlerWithUrl(String ip, List<Object> urls) {
		JSONObject virusAll = DataFactory.getVirustatolInstance().getIpReport(ip);
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
					urls.add(url);
				}
			}
//			System.out.println(urls);
		}
	}
	
	//ok
	public static void cymonIpHandlerWithUrl(String ip, List<Object> urls) {
		JSONObject urlAll = DataFactory.getCymonInstance().getIpReportWithUrl(ip);
		JSONArray urlArray = null;
		try {
			urlArray = urlAll.getJSONArray("results");
		}catch (Exception e) {
			urlArray = new JSONArray();
		}
		if (!urlArray.isEmpty()) {
			for (Object object : urlArray) {
				String url = "";
				try {
					url = ((JSONObject)object).getString("location");
				}catch (Exception e) {
					url = "";
				}
				if (!"".equals(url)) {
					urls.add(url);
				}
			}
//			System.out.println(urls);
		}
	}
	
	public static void cymonIpHandlerWithDomain(String ip, List<Object> domains) {
		JSONObject domianAll = DataFactory.getCymonInstance().getIpReportWithDomain(ip);
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
					domains.add(domain);
				}
			}
		}
	}
	
	
	public static void cymonIpHandlerWithIntellAndEvent(String ip, List<Object> intelligents, List<Object> detailUrl) {
		JSONObject cyAll = DataFactory.getCymonInstance().getIpReportWithEvent(ip);
		JSONArray cyArray = null;
//		List<CymonIntell> cymonIntells = new ArrayList<>();
		try {
			cyArray = cyAll.getJSONArray("results");
		}catch (Exception e) {
			cyArray = new JSONArray();
		}
//		System.out.println(cyArray);
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
				deurl.event_url = detail;
				deurl.time = update;
				cymonIntell.description = description;
				cymonIntell.tag = tag;
				cymonIntell.time = time;
				detailUrl.add(deurl);
				intelligents.add(cymonIntell);
			}
//			System.out.println(intelligents);
		}
	}
	
	public static void ibmIpHandlerWithIntell(String ip, List<Object> intelligents) {
		JSONObject all = DataFactory.getIBMInstance().getIpReport(ip);
		JSONArray array = null;
//		List<IBMIntell> intelligents = new ArrayList<>();
	    try {
	    	array = all.getJSONArray("history");
	    }catch (Exception e) {
			array = new JSONArray();
		}
	    if (!array.isEmpty()) {
	    	for (Object json : array) {
	    		String cat = "", reasonDescription = "", created = "";
	    		try {
	    			cat = ((JSONObject)json).getString("cats");
	    		}catch(Exception e) {
	    			cat = "";
	    		}
	    		try {
	    			reasonDescription = ((JSONObject)json).getString("reasonDescription");
	    		}catch(Exception e) {
	    			reasonDescription = "";
	    		}
	    		try {
	    			created = ((JSONObject)json).getString("created");
	    		}catch(Exception e) {
	    			created = "";
	    		}
	    		IBMIntell intelligent = new IBMIntell();
				intelligent.description = reasonDescription;
				intelligent.time = created;
				intelligent.type = cat;
				intelligent.source = "open IBM";
				intelligents.add(intelligent);
			}
//	    	System.out.println(intelligents);
	    }
	}
	
	public static void ipHandler(String ip) {
		List<Object> intelligents = new ArrayList<>();   //intellegent
		List<Object> detailUrl = new ArrayList<>();      //event
		List<Object> urls = new ArrayList<>();           //url
		List<Object> domains = new ArrayList<>();
		Set<Object> malware = new HashSet<>();
		
		if (ip.length() <= 15) {
			cymonIpHandlerWithIntellAndEvent(ip,intelligents, detailUrl);  //cymon intellegent & event
			cymonIpHandlerWithUrl(ip, urls);		// cymon url
			cymonIpHandlerWithDomain(ip, domains);
			cymonIpHandlerWithMalware(ip, malware);
		}
		
		ibmIpHandlerWithIntell(ip,intelligents);  //ibm intellegent
		ibmIpHandlerWithMalware(ip, malware);
		
		virustotalIpHandlerWithMalware(ip, malware);
		virustotalIpHandlerWithUrl(ip,urls);    //virustoatal url
		
		SearchIp searchIp = new SearchIp();
		searchIp.ip = ip;
		searchIp.intelligence = intelligents.toString();
		searchIp.event = detailUrl.toString();
		searchIp.time = new Date();
		searchIp.url = urls.toString();
		searchIp.domain = domains.toString();
		searchIp.malware = malware.toString();
		searchIp.save();
	}
	
	public static JSONObject getIp(String cate) {
		JSONObject all = new IBMUtil().getIpAccordingCategory(cate);
//		System.out.println(all);
		JSONArray array = all.getJSONArray("rows");
		if (array != null) {
			for (Object json : array) {
				String ip = ((JSONObject)json).getString("ip");
				double score = ((JSONObject)json).getDouble("score");
				String created = ((JSONObject)json).getString("created");
				IP ip1 = new IP();
				ip1.category = cate;
				ip1.created = created;
				ip1.ip = ip;
				ip1.score = score;
				ip1.save();
			}
		}
		return all;
	}
	
}	

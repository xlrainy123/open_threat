package job;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;

import models.SearchIp;
import okhttp3.OkHttpClient;
import utils.model.IntellegentInterface;

public class IPHandler implements Runnable{
	private final CountDownLatch count = new CountDownLatch(3);
	private CountDownLatch handlerCount;
	public String ip;
	public IPHandlerWithIBM ibm;
	public IPHandlerWithVirustotal virustotal;
	public IPHandlerWithCymon cymon;
	public OkHttpClient client = null;
	public List<IntellegentInterface> intelligents = Collections.synchronizedList(new ArrayList<>());   //intellegent
	public List<Object> detailUrl = Collections.synchronizedList(new ArrayList<>());  //event
	public List<Object> urls = Collections.synchronizedList(new ArrayList<>());           //url
	public List<Object> domains = Collections.synchronizedList(new ArrayList<>());
	public Set<Object> malware = Collections.synchronizedSet(new HashSet<>());
	//tong bu set
	private Set<SearchIp> ipSet;
	
	public IPHandler(String ip, OkHttpClient client, CountDownLatch handlerCount,
			Set<SearchIp> ipSet) {
		this.ip = ip;
		this.client = client;
		this.handlerCount = handlerCount;
		this.ipSet = ipSet;
	}
	public void init() {
		ibm = new IPHandlerWithIBM(count, client, malware, intelligents);
		ibm.ip = ip;
		
		virustotal = new IPHandlerWithVirustotal(count, client, malware, urls);
		virustotal.ip = ip;
		
		cymon = new IPHandlerWithCymon(count, client, intelligents,
						detailUrl, urls, domains, malware);
		cymon.ip = ip;
	}
	public void execute() {
		Thread ibmThread = new Thread(ibm);
		Thread virustotalThread = new Thread(virustotal);
		Thread cymonThread = new Thread(cymon);
		ibmThread.start();
		virustotalThread.start();
		if (ip.length() <= 15) {
			cymonThread.start();  // zan shi bu shi yong cymon
			try {
				count.await();
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}else {
			count.countDown();
			try {
				count.await();
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
		System.out.println("----------ibmThread complete :" + ibm.complete);
		System.out.println("----------virustotalThread complete :" + virustotal.complete);
		System.out.println("----------cymonThread complete :" + cymon.complete);
//		intelligents.addAll(cymon.intelligents);
//		intelligents.addAll(ibm.intelligents);
		Collections.sort(intelligents, new Comparator<IntellegentInterface>() {
			@Override
			public int compare(IntellegentInterface o1, IntellegentInterface o2) {
				String time1 = o1.time, time2 = o2.time;
				if ("".equals(time1) || "".equals(time2)) {
					return 0;
				}
				String[] time1s = time1.trim().split("T");
				String[] time2s = time2.trim().split("T");
				Date date1 = null;
				Date date2 = null;
				SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd");
				try {
					date1 = format.parse(time1s[0]);
					date2 = format.parse(time2s[0]);
				} catch (ParseException e) {
					return time2.compareTo(time1);
				}
				return date2.compareTo(date1);
			}
			
		});
		detailUrl.addAll(cymon.detailUrl);
		urls.addAll(cymon.urls);
		urls.addAll(virustotal.urls);
		domains.addAll(cymon.domains);
		malware.addAll(cymon.malware);
		malware.addAll(ibm.malware);
		malware.addAll(virustotal.malware);
		SearchIp searchIp = new SearchIp();
		searchIp.ip = ip;
		searchIp.intelligence = intelligents.toString();
		searchIp.event = detailUrl.toString();
		searchIp.time = new Date();
		searchIp.url = urls.toString();
		searchIp.domain = domains.toString();
		searchIp.malware = malware.toString();
		ipSet.add(searchIp);
	}
	@Override
	public void run() {
		System.out.println("--------IPHandler-------");
		init();
		execute();
		handlerCount.countDown();
	}
}

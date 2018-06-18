package job;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import models.IP;
import models.SearchIp;
import okhttp3.OkHttpClient;
import utils.HttpUtils;

public class Client{
	private CountDownLatch count;
	private Set<SearchIp> ipSet = Collections.synchronizedSet(new HashSet<>());
	
	public Client(int jobNum) {
		this.count = new CountDownLatch(jobNum);
	}
	
	public void execute(List<IP> ips) {
		System.out.println("0-------------");
		OkHttpClient client = null;
		try {
			client = HttpUtils.getHttpClient(true);
		} catch (KeyManagementException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		List<Thread> threads = new ArrayList<>();
		for (int i = 0; i < ips.size(); i++) {
			IP ip = ips.get(i);
			IPHandler hanlder = new IPHandler(ip.ip , client, count, ipSet);
			Thread thread = new Thread(hanlder);
			threads.add(thread);
		}
		for (Thread thread : threads) {
			thread.start();
		}
		try {
			count.await();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		for (SearchIp ip : ipSet) {
			System.out.println(ip.ip);
			ip.save();
		}
	}
}
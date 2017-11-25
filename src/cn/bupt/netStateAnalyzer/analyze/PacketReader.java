package cn.bupt.netStateAnalyzer.analyze;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.tcpip.Http.Request;

import android.annotation.SuppressLint;
import android.util.Log;

/**
 * packet reader 提供算法解析出qos数据 
 * 第三方opensource  jNetCap。jar
 */
@SuppressLint("NewApi")
public class PacketReader {
	public static ArrayList<JPacket> packets;

	public static String localIP;
	public String pcapFileName;

	public static boolean[] retTable;
	public static HashMap<Integer, Integer> rttMap;
	public long pktTime;
	public static float pktLoss;
	public static int avrRtt;
	public static int avrDns;
	public static int avrRes;
	public static long avrTime;
	public static long avrSpeed;
	public static double delayJitter;
	public static long traffic = 0;
	public static int threadNum;
	public static int advertise_num;
	public static int advertise_traffic;
	public static float res_efficiency;
	public static float ssl;
	public static float tradeTime = 0;
	private static int ssl_num = 0;
	public static double businessEff = 0;
	private int otherTraffic = 0;
	
	public static String visitUrl;

	public HashSet<String> httpUrl = new HashSet<String>();
	public HashMap<String, Integer> dnsTime = new HashMap<String, Integer>();
	public HashMap<Integer, Integer> rrMap = new HashMap<Integer, Integer>();

	private String[] ipList;
	
	private static Ip4 ip4 = new Ip4();
	private static Ip6 ip6 = new Ip6();
	private static Tcp tcp = new Tcp();
	private static Udp udp = new Udp();
	private static Http http = new Http();
	
	static {
		System.loadLibrary("jnetpcap");
	}


	public PacketReader(String[] ipList, String localIpAddr, String pcapFileName) {
		super();
		this.ipList = ipList;
		localIP = localIpAddr;
		this.pcapFileName = pcapFileName;
		packets = new ArrayList<JPacket>();
		listPackets();
	}

	/**
	 * read qos 参数
	 * 
	 */
	public void read(String localIP, String pcapFileName,
			OnReadComplete onReadComplete, int pkgType) {

		retTable = new boolean[packets.size()];
		rttMap = new HashMap<Integer, Integer>();

		pktTime = getPktTime();//总时间 
		traffic = getTraffic();//original packet length
		
		businessEff = getBusinessEff();//business效率，要capture 的包的长度除以总的长度
		
		avrDns = getDns();// dns时延
		avrRtt = getRtt();// tcp连接时延，网页连接时延
		pktLoss = getRetTimes();// 丢包率
		
		switch (pkgType) {
		case ScoreStatisticsSuper.WEB:
			avrRes = getHttpResponse();// 网页响应时延
			avrTime = getAvrTime();// 网页下载时延以及下载文件时延
			avrSpeed = getAvrSpeed();
			break;
		case ScoreStatisticsSuper.DOWNLOAD:
			avrTime = getAvrTime();// 网页下载时延以及下载文件时延
			threadNum = getThreadNum();// 获取进程数
			avrSpeed = getAvrSpeed();
			break;
		case ScoreStatisticsSuper.VIDEO:
			avrRes = getHttpResponse();// 网页响应时延
			delayJitter = getDelayJitter();
			avrSpeed = getAvrSpeed();
			break;
		case ScoreStatisticsSuper.GAME:
			avrRes = getHttpResponse();// 网页响应时延
			avrSpeed = getAvrSpeed();
			advertise_num = getAdvertisement();
			res_efficiency = getResrcEfficiency();
			break;
		case ScoreStatisticsSuper.TRADE:
			delayJitter = getDelayJitter();
			ssl = getSSL();// 安全系数
			tradeTime = getTradeTime();
			break;
		case ScoreStatisticsSuper.SOCIAL:
		default:
		}
		onReadComplete.onComplete();
	}

	/**
	 * 把 pcap file 转化为 Jpacket的arraylist
	 * 
	 */
	private void listPackets() {
		otherTraffic = 0;
		StringBuilder errbuf = new StringBuilder();
		Pcap pcap = Pcap.openOffline(pcapFileName, errbuf);
		JPacketHandler<String> handler = new JPacketHandler<String>() {

			@Override
			public void nextPacket(JPacket packet, String user) {
				if (filterByIp(packet, ipList)){
					packets.add(packet);
				} else {
					otherTraffic += packet.getPacketWirelen();
				}
			}
		};
		try {
			pcap.loop(-1, handler, null);
		} finally {
			pcap.close();
		}
	}


	private static String getServerIp(JPacket pkt) { 
		String ip = "";
		byte[] addr;
		if (pkt.hasHeader(Tcp.ID)) {
			pkt.getHeader(tcp);
			if (pkt.hasHeader(Ip4.ID)) {
				pkt.getHeader(ip4);
				ip = FormatUtils.ip(ip4.source());
				if (ip.equals(localIP)) {
					ip = FormatUtils.ip(ip4.destination());	
				}
			} else if (pkt.hasHeader(Ip6.ID)) {
				pkt.getHeader(ip6);
				addr = (tcp.destination() < 1024) ? ip6.destination() : ip6.source();
				ip = FormatUtils.asStringIp6(addr, true);
			}
		} else if (pkt.hasHeader(Udp.ID)) {
			pkt.getHeader(udp);
			if (pkt.hasHeader(Ip4.ID)) {
				pkt.getHeader(ip4);
				ip = FormatUtils.ip(ip4.source());
				if (ip.equals(localIP)) {
					ip = FormatUtils.ip(ip4.destination());	
				}
			} else if (pkt.hasHeader(Ip6.ID)) {
				pkt.getHeader(ip6);
				addr = (udp.destination() > 1024) ? ip6.destination() : ip6.source();
				ip = FormatUtils.asStringIp6(addr, true);
			}
		}
		return ip;
	}


	private boolean filterByIp(JPacket pkt, String[] ipList) {
		if (localIP == null) {
			//Log.e("FilterByIp", "Local ip is null!");
			return false;
		}
		if (isDnsPkt(pkt)) {
			return true;
		}
		if (ipList == null || ipList.length == 0) {
			//Log.e("FilterByIp", "Ip list is null or empty! Do not filter packets!");
			return true;
		}
		String ip = getServerIp(pkt);
		if (ip.equals("")) {
			//Log.e("FilterByIp", "Remote ip is empty!");
			return false;
		}
		for (String s : ipList) {
			if (ip.equals(s)) {
				return true;
			}
		}
		return false;
	}


	private int getRtt() {
		int rtt, totRtt = 0, cnt = 0;
		long ack = 0, seq = 0, t2 = 0;
		JPacket p = null;
		Tcp h = new Tcp();
		int psize = packets.size();
		HashMap<Integer, Long[]> map = new HashMap<Integer, Long[]>();
		for (int i = 0; i < psize; i++) {
			p = packets.get(i);
			if (p.hasHeader(Tcp.ID)) {
				p.getHeader(h);
				if (h.flags() != 0x10) { 
					ack = h.ack();
					seq = h.seq();
					t2 = p.getCaptureHeader().timestampInMicros();
					map.put(i, new Long[] { ack, seq, t2 });
				}
				if (h.flags() != 0x02) { 
					ack = h.ack();
					seq = h.seq();
					Set<Integer> s = map.keySet();
					for (Integer m : s) {
						if (m.intValue() == i) {
							continue;
						}
						Long[] val = map.get(m);
						if (ack == (val[1] + 1) || seq == val[0]) {
							map.remove(m);
							rtt = (int) (p.getCaptureHeader().timestampInMicros() - val[2]);
							if (rtt < 500000) {
								rttMap.put(i, rtt);
								rrMap.put(m, i);
								totRtt += rtt;
								cnt++;
							}
							break;
						}
					}
				}
			}
		}
		return cnt > 0 ? totRtt / cnt : 0;
	}


	private float getRetTimes() {
		int cnt = 0;
		int psize = packets.size();
		long seq, pseq;
		String key = "";
		Tcp h = new Tcp();
		JPacket p = null;
		HashMap<String, Long> map = new HashMap<String, Long>();
		for (int i = 0; i < psize; i++) {
			p = packets.get(i);
			if (p.hasHeader(Tcp.ID)) {
				p.getHeader(h);
				seq = h.seq();
				key = (h.source() > 1023) ? 
						("C" + h.source()) : ("S" + h.destination());
				if (map.containsKey(key)) {
					pseq = map.get(key);
					if (pseq < seq) {
						map.put(key, seq);
					} else if (pseq > seq) {
						cnt++;
						//Log.i(key, "" + i);
						retTable[i] = true;
					}
				} else {
					map.put(key, seq);
				}
			}
		}
		return psize > 0 ? ((float) cnt) / psize : 0;
	}


	private int getDns() {
		long t1 = 0;
		int transId = 0, plOff = 0;
		int offset = 0, size = 0;
		int cnt = 0, totDns = 0;
		int psize = packets.size();
		JPacket p;
		byte[] url = null;
		for (int i = 0; i < psize; i++) {
			p = packets.get(i);
			if (p.hasHeader(Udp.ID)) {
				Udp udp = new Udp();
				p.getHeader(udp);
				if (udp.destination() == 53) {
					plOff = udp.getPayloadOffset();
					offset = plOff + 12 + 1;
					size = udp.getPayloadLength() - (12 + 4 + 2);
					transId = (p.getByte(plOff) << 8) & 0xFF00 | p.getByte(plOff + 1) & 0xFF;
					url = p.getByteArray(offset, size);
					t1 = p.getCaptureHeader().timestampInMicros();
				} else if (udp.source() == 53 && transId != 0) {
					int tmpId = (p.getByte(plOff) << 8) & 0xFF00 | p.getByte(plOff + 1) & 0xFF;
					if (transId == tmpId) {
						int dns = (int) (p.getCaptureHeader().timestampInMicros() - t1);
						dnsTime.put(new String(url) + "~" + i, dns);
						totDns += dns;
						cnt++;
						transId = 0;
					}
				}
			}
		}
		return cnt > 0 ? totDns / cnt : 0;
	}
	

	private static boolean isDnsPkt(JPacket p) {
		if (p != null && p.hasHeader(Udp.ID)) {
			p.getHeader(udp);
			if (udp.destination() == 53 || udp.source() == 53) {
				return true;
			} 
		}
		return false;
	}


	private int getHttpResponse() {
		int totRes = 0, cnt = 0;
		int psize = packets.size();
		JPacket p;
		String s = null;
		for (int i=0;i<psize;i++) {
			p = packets.get(i);
			if (p.hasHeader(Http.ID)) {
				p.getHeader(http);
				s = http.fieldValue(Request.Host);
				Integer res = rrMap.get(i);
				if (s != null && res != null) {
					String get = s + http.fieldValue(Request.RequestUrl); 
					int r = rttMap.get(res);
					httpUrl.add(s);
					Log.i("ResponseTime", get + ":" + r);
					totRes += r;
					cnt++;
				}	
			}
		}
		visitUrl = getUrl();
		Log.i("HttpUrl" , visitUrl);
		return cnt > 0 ? totRes/cnt : 0;
	}
	

	private String getUrl() {
		String all = "";
		if (httpUrl != null) {
			for (String s : httpUrl) {
				all += (s + "~");
			}
		}
		return all.equals("") ? "null" : all;
	}
	
	/**
	 * 程序通过查看数据中客户端对服务器资源请求的情况来识别多线程
	 * 
	 */
	private int getThreadNum() { 
		HashSet<String> hs = new HashSet<String>();
		int psize = packets.size();
		JPacket p;
		String s = null;
		for (int i = 0; i < psize; i++) {
			p = packets.get(i);
			if (p.hasHeader(Http.ID)) {
				http = new Http();
				p.getHeader(http);
				s = http.fieldValue(Request.RequestUrl);
				if (s != null && 
					(s.contains(".mp3") || s.contains(".m4a") || s.contains(".apk"))) {
					hs.add(s); 
				}
			}
		}
		return hs.size() == 0 ? 1 : hs.size();
	}


	private long getPktTime() {
		long pktTime = 0;
		long t1, t2;
		int psize = packets.size();
		if (psize > 0) {
			JPacket p;
			p = packets.get(0);
			t1 = p.getCaptureHeader().timestampInMicros();
			p = packets.get(psize - 1);
			t2 = p.getCaptureHeader().timestampInMicros();
			pktTime = t2 - t1;
		}
		return pktTime;
	}


	private long getAvrTime() {
		int n = httpUrl.size();
		return (pktTime / (n > 0 ? n : 1));
	}

	private long getAvrSpeed() {
		return pktTime > 0 ? (long) ((traffic / (pktTime + 0.0)) * 1000000) : 0;
	}

	/**
	 * 基于getRtt函数获取的TCP时延数据，通过标准差计算时延抖动
	 * 
	 */
	private double getDelayJitter() {
		int n = rttMap.size();
		double tmp = 0;
		double sum = 0;
		for (int s : rttMap.values()) {
			tmp = s - avrRtt;
			sum += tmp * (tmp / n);
		}
		
		return Math.sqrt(sum);
	}

	/**
	 * 程序通过查看数据中所包含的HTTP请求资源的url识别来获
	 * 取广告信息流量及数目的获取
	 * */
	private int getAdvertisement() {
		int cnt = 0;
		for (int i = 0; i < packets.size(); i++) {
			JPacket p = packets.get(i);
			if (p.hasHeader(Http.ID)) {
				p.getHeader(http);
				String s = http.fieldValue(Request.RequestUrl);
				if (s != null && (s.contains(".jpg") || s.contains(".png"))) {
					cnt++;
				}
			}
		}
		return cnt;
	}

	/**
	 * 程序通过识别并获取业务有效资源及
	 * 总数据包资源，相除后得到
	 * */
	private float getResrcEfficiency() { // 百分之
		int payloadbytes = 0;
		int totalbytes = 0;
		float effrate;
		for (int i = 0; i < packets.size(); i++) {
			JPacket p = packets.get(i);
			if (p.hasHeader(Tcp.ID)) {
				if (p.hasHeader(Http.ID)) {
					p.getHeader(http);
					payloadbytes += http.getPayloadLength();
					Log.d("ren", "payloadbytes is " + payloadbytes);
				} else {
					p.getHeader(tcp);
					payloadbytes += tcp.getPayloadLength();
					Log.d("ren", "payloadbytes is " + payloadbytes);
				}
			} else if (p.hasHeader(Udp.ID)) {

			} else {

			}
			totalbytes += p.getPacketWirelen();
			Log.d("ren", "totalbytes is " + totalbytes);
		}
		Log.i("ren", "payload size is " + payloadbytes + "B.totalsize is "
				+ totalbytes + " B");
		effrate = (float) payloadbytes / (float) totalbytes;
		float a = (float) Math.round(effrate * 10000) / 100;
		Log.i("ren", "effiticv is " + a);
		return a;
	}

	/**
	 * 程序通过识别并获取数据包中通过加密协议传输的情况
	 * 来相对地分析业务的安全性
	 */
	private float getSSL() {
		int cnt = 0;
		int psize = packets.size();
		int pktLen = 0;
		int plOff = 0;
		byte[] id1, id2;
		Tcp h = new Tcp();
		JPacket p = null;
		for (int i = 0; i < psize; i++) {
			p = packets.get(i);
			pktLen = p.size();
			if (p.hasHeader(Tcp.ID)) {
				p.getHeader(h);
				plOff = h.getPayloadOffset();
				int offset = plOff + 1;
				if ((offset + 2) < pktLen) {
					id1 = p.getByteArray(offset, 2);
					id2 = p.getByteArray(pktLen - 8, 2);
					if (((id1[0] << 8) & 0xFF00 | id1[1] & 0xFF) == 0x0301
							|| ((id2[0] << 8) & 0xFF00 | id2[1] & 0xFF) == 0x0301) {
						Log.i("SSL ", " " + (i + 1));
						cnt++;
						if (ssl_num == 0) {
							ssl_num = i;
						}
						if (rrMap.containsKey(i) || rrMap.containsValue(i)) {
							cnt++;
						}
					}
				}
			}
		}
		return ((float) cnt) / psize;
	}


	private float getTradeTime() {
		long t1 = 0,t2 = 0;
		int psize = packets.size();
		JPacket p = null;
		if(ssl_num > 0){
			p = packets.get(ssl_num);
			t1 = p.getCaptureHeader().timestampInMicros();
			p = packets.get(psize - 1);
			t2 = p.getCaptureHeader().timestampInMicros();
			tradeTime = t2 - t1;
		}
		return tradeTime;
	}
	
	private long getTraffic() {
		long sum = 0;
		for (JPacket p : packets) {
			sum += p.getPacketWirelen();
		}
		return sum;
	}
	
	private double getBusinessEff() {
		//long fileLen = new File(pcapFileName).length();
		long tmp = traffic + otherTraffic;
		return tmp != 0 ? (traffic / (tmp + 0.0)) : 0;
	}
	
}

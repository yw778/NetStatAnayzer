package cn.bupt.netStateAnalyzer.analyze;

/**
 * 社交类score评测 
 */

public class SocialScoreStatistics extends ScoreStatisticsSuper{
	

	public SocialScoreStatistics() {
        this.scoreWeight = new ScoreWeight(0, 0.2, 0.2, 0, 0, 0, 0.3, 0,
                0.3, 0, 0, 0, 0, 0, 0);
    }
   
    protected int dnsScore(int dns) { // unit: us
        return (int) (dns > 0 ? 20910.0 / (209.1 + 0.001 * dns) : 0);
    }

    protected int tcpScore(int tcp) { // unit: us
        return dnsScore(tcp);
    }
    
    protected int pktLossScore(float loss) {
        return (int) (100 * (1 - loss));
    }
    
    protected int trafficScore(long traffic){// unit: B
    	float a = (float) (traffic / 1024.0);
    	int s = (int) (100 * Math.exp(-0.001107 * a));
    	return s < 0 ? 0 : s;
    }
	@Override
	public int totalScore(PacketReader reader) {
		// TODO Auto-generated method stub
		return (int) (this.scoreWeight.weightDnsScore * dnsScore(reader.avrDns)
                + this.scoreWeight.weightTcpScore * tcpScore(reader.avrRtt)
                + this.scoreWeight.weightPacketlossScore
                * pktLossScore(reader.pktLoss) + this.scoreWeight.weightTrafficScore
                * trafficScore(reader.traffic));
	}
}

package cn.bupt.netStateAnalyzer.analyze;

/**
 * ScoreStatistics
 * 父类
 * 
 */
public abstract class ScoreStatisticsSuper {
    public static final int WEB = 0;
    public static final int DOWNLOAD = 1;
    public static final int VIDEO = 2;
    public static final int TRADE = 3;
    public static final int GAME = 4;
    public static final int SOCIAL = 5;
    public static final int OTHER = 6;
    public ScoreWeight scoreWeight;

    public abstract int totalScore(PacketReader reader);

    public void setWeight(ScoreWeight w) {
        this.scoreWeight = w;
    }
}

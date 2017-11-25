package cn.bupt.netStateAnalyzer.analyze;

/**
 * score类的工厂设计模式
 * 
 */
public class ScoreStatisticsFactory {
    public static ScoreStatisticsSuper create(int type) {
        switch (type) {
        case ScoreStatisticsSuper.WEB:
            return new WebScoreStatistics();
        case ScoreStatisticsSuper.DOWNLOAD:
        	return new DownloadScoreStatistics();
        case ScoreStatisticsSuper.VIDEO:
            return new VideoScoreStatistics();
        case ScoreStatisticsSuper.TRADE:
        	return new TradeScoreStatistics();
        case ScoreStatisticsSuper.GAME:
        	return new GameScoreStatistics();
        case ScoreStatisticsSuper.SOCIAL:
        	return new SocialScoreStatistics();
        default:
            return new DefaultScoreStatistics();
        }
    }
}

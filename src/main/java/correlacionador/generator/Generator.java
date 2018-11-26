package correlacionador.generator;

import java.io.FileInputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Properties;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.http.HttpHost;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.get.GetIndexRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;

public class Generator {

	class Props {

		String elasticHost;
		int elasticPort1;
		int elasticPort2;

		boolean logDocuments;
		ArrayList<String> yearMonth = new ArrayList<String>();
		ArrayList<String> matchingMti = new ArrayList<String>();
		ArrayList<String> issuerProduct = new ArrayList<String>();
		ArrayList<String> authorizedResponseCodes = new ArrayList<String>();
		ArrayList<String> suspiciousResponseCodes = new ArrayList<String>();
		ArrayList<String> declinedResponseCodes = new ArrayList<String>();
		ArrayList<Integer> maxIntervalBetweenRquests = new ArrayList<Integer>();
		ArrayList<Integer> maxTransactionResponseTime = new ArrayList<Integer>();
		ArrayList<Integer> socketDisconnectedEvery = new ArrayList<Integer>();
		ArrayList<Integer> socketTimeoutEvery = new ArrayList<Integer>();
		ArrayList<Integer> nonResponseRequestEvery = new ArrayList<Integer>();
		ArrayList<Integer> notHonoredResponseCodeEvery = new ArrayList<Integer>();
		ArrayList<Integer> suspiciousResponseCodeEvery = new ArrayList<Integer>();
		ArrayList<Integer> declinedResponseCodeEvery = new ArrayList<Integer>();
		ArrayList<String> serverIp = new ArrayList<String>();

		Random random = new Random(System.currentTimeMillis());
		ArrayList<String> responseCodes = new ArrayList<String>(Arrays.asList("00", "01", "02", "03", "04", "05", "06",
				"07", "08", "09", "10", "11", "12", "13", "14", "15", "16", "17", "19", "20", "21", "22", "25", "28",
				"30", "41", "43", "51", "52", "53", "54", "55", "57", "58", "59", "61", "62", "63", "65", "68", "75",
				"76", "77", "78", "80", "81", "82", "83", "85", "91", "92", "93", "94", "95", "96", "B1", "N0", "N3",
				"N4", "N7", "P2", "P5", "P6", "Q1", "R0", "R1", "R3", "XA", "XD", "Z3"));

		int nextSocketDisconnected;
		int nextSocketTimeout;
		int nextNonResponseRequest;
		int nextNotHonoredResponseCode;
		int nextSuspiciousResponseCode;
		int nextDeclinedResponseCode;

		int incidentStarted = -1;
		int incidentCount;

		long start;
		String yearMonthPrev = "yyyyMM";

		int numRequests = 0;
		RestHighLevelClient client = null;
		String indexName;

		Props() throws Exception {
			doLoadProps();
			doInit();
		}

		private void doLoadProps() throws Exception {

			Properties prop = new Properties();
			prop.load(new FileInputStream("res/instant.config.properties"));

			elasticHost = prop.getProperty("generator.elastic-host").trim();
			elasticPort1 = Integer.valueOf(prop.getProperty("generator.elastic-port").trim().split(",")[0].trim());
			//elasticPort2 = Integer.valueOf(prop.getProperty("generator.elastic-port").trim().split(",")[1].trim());

			logDocuments = prop.getProperty("generator.log-documents").equals("yes") ? true : false;

			for (String string : prop.getProperty("generator.year-month").trim().split(",")) {
				yearMonth.add(string.trim());
			}
			for (String string : prop.getProperty("generator.matching-mti").trim().split(",")) {
				matchingMti.add(string);
			}
			int lines = Integer.valueOf(prop.getProperty("generator.issuer-product-lines").trim());
			for (int i = 1; i <= lines; i++) {
				for (String string : prop.getProperty("generator.issuer-product-line-" + i).trim().split(",")) {
					issuerProduct.add(string);
				}
			}
			for (String string : prop.getProperty("generator.authorized-response-codes").trim().split(",")) {
				authorizedResponseCodes.add(string.trim());
			}
			for (String string : prop.getProperty("generator.suspicious-response-codes").trim().split(",")) {
				suspiciousResponseCodes.add(string.trim());
			}
			for (String string : prop.getProperty("generator.declined-response-codes").trim().split(",")) {
				declinedResponseCodes.add(string.trim());
			}
			for (String string : prop.getProperty("generator.max-interval-between-requests").trim().split(":")) {
				maxIntervalBetweenRquests.add(Integer.valueOf(string));
			}
			for (String string : prop.getProperty("generator.max-transaction-response-time").trim().split(":")) {
				maxTransactionResponseTime.add(Integer.valueOf(string));
			}
			for (String string : prop.getProperty("generator.socket-disconnected-every").trim().split(":")) {
				socketDisconnectedEvery.add(Integer.valueOf(string));
			}
			for (String string : prop.getProperty("generator.socket-timeout-every").trim().split(":")) {
				socketTimeoutEvery.add(Integer.valueOf(string));
			}
			for (String string : prop.getProperty("generator.nonresponse-request-every").trim().split(":")) {
				nonResponseRequestEvery.add(Integer.valueOf(string));
			}
			for (String string : prop.getProperty("generator.nothonored-response-code-every").trim().split(":")) {
				notHonoredResponseCodeEvery.add(Integer.valueOf(string));
			}
			for (String string : prop.getProperty("generator.suspicious-response-code-every").trim().split(":")) {
				suspiciousResponseCodeEvery.add(Integer.valueOf(string));
			}
			for (String string : prop.getProperty("generator.declined-response-code-every").trim().split(":")) {
				declinedResponseCodeEvery.add(Integer.valueOf(string));
			}
			for (String string : prop.getProperty("generator.server-ip").trim().split(":")) {
				serverIp.add(string);
			}

		}

		private void doInit() throws IOException {
			client = new RestHighLevelClient(RestClient.builder(new HttpHost(elasticHost, elasticPort1, "http")));
					//,new HttpHost(elasticHost, elasticPort2, "http")));
		}

		public void setNextEvent(int e) {
			switch (e) {
			case 0:
				nextSocketDisconnected = random.nextInt(socketDisconnectedEvery.get(1) - socketDisconnectedEvery.get(0))
						+ socketDisconnectedEvery.get(0) + 1;
				break;
			case 1:
				nextSocketTimeout = random.nextInt(socketTimeoutEvery.get(1) - socketTimeoutEvery.get(0))
						+ socketTimeoutEvery.get(0) + 1;
				break;
			case 2:
				nextNonResponseRequest = random.nextInt(nonResponseRequestEvery.get(1) - nonResponseRequestEvery.get(0))
						+ nonResponseRequestEvery.get(0) + 1;
				break;
			case 3:
				nextNotHonoredResponseCode = random
						.nextInt(notHonoredResponseCodeEvery.get(1) - notHonoredResponseCodeEvery.get(0))
						+ notHonoredResponseCodeEvery.get(0) + 1;
				break;
			case 4:
				nextSuspiciousResponseCode = random
						.nextInt(suspiciousResponseCodeEvery.get(1) - suspiciousResponseCodeEvery.get(0))
						+ suspiciousResponseCodeEvery.get(0) + 1;
				break;
			case 5:
				nextDeclinedResponseCode = random
						.nextInt(declinedResponseCodeEvery.get(1) - declinedResponseCodeEvery.get(0))
						+ suspiciousResponseCodeEvery.get(0) + 1;
				break;
			default:
				nextSocketDisconnected = random.nextInt(socketDisconnectedEvery.get(1) - socketDisconnectedEvery.get(0))
						+ socketDisconnectedEvery.get(0) + 1;
				nextSocketTimeout = random.nextInt(socketTimeoutEvery.get(1) - socketTimeoutEvery.get(0))
						+ socketTimeoutEvery.get(0) + 1;
				nextNonResponseRequest = random.nextInt(nonResponseRequestEvery.get(1) - nonResponseRequestEvery.get(0))
						+ nonResponseRequestEvery.get(0) + 1;
				nextNotHonoredResponseCode = random
						.nextInt(notHonoredResponseCodeEvery.get(1) - notHonoredResponseCodeEvery.get(0))
						+ notHonoredResponseCodeEvery.get(0) + 1;
				nextSuspiciousResponseCode = random
						.nextInt(suspiciousResponseCodeEvery.get(1) - suspiciousResponseCodeEvery.get(0))
						+ suspiciousResponseCodeEvery.get(0) + 1;
				nextDeclinedResponseCode = random
						.nextInt(declinedResponseCodeEvery.get(1) - declinedResponseCodeEvery.get(0))
						+ declinedResponseCodeEvery.get(0) + 1;
			}

		}
	}

	class Msg {
		String yearMonth;
		String day;
		String mtiRequest;
		String mtiResponse;
		String responseCode;
		String key;
		String type;
		long start;
		int responseTime;
		String bin;
		String issuer;
		String product;
		String hostIp;
		Msg() {

			yearMonth = new SimpleDateFormat("yyyyMM").format(new Date(props.start));
			day = new SimpleDateFormat("dd").format(new Date(props.start));

			int m = props.random.nextInt(props.matchingMti.size());
			mtiRequest = props.matchingMti.get(m).split(":")[0];
			mtiResponse = props.matchingMti.get(m).split(":")[1];

			if (props.incidentStarted == -1) ;
			else props.incidentCount++;

			switch (props.incidentStarted) {
			case -1:
				responseCode = props.authorizedResponseCodes
						.get(props.random.nextInt(props.authorizedResponseCodes.size()));
				type = "AUTHORIZED";
				break;
			case 2:
				break;
			case 3:
				while (true) {
					String rc = props.responseCodes.get(props.random.nextInt(props.responseCodes.size()));
					if (props.authorizedResponseCodes.contains(rc) || props.suspiciousResponseCodes.contains(rc)
							|| props.declinedResponseCodes.contains(rc))
						continue;
					responseCode = rc;
					break;
				}
				type = "NOTHONORED";
				break;
			case 4:
				responseCode = props.suspiciousResponseCodes
						.get(props.random.nextInt(props.suspiciousResponseCodes.size()));
				type = "SUSPICIOUS";
				break;
			case 5:
				responseCode = props.declinedResponseCodes
						.get(props.random.nextInt(props.declinedResponseCodes.size()));
				type = "DECLINED";
				break;
			default:
				LOGGER.info("::: ErrorCraso: IncidentStarted invalid: " + props.incidentStarted);
				break;
			}

			key = String.format(new SimpleDateFormat("yyDDD").format(new Date(props.start)) + "%07d", props.numRequests)
					+ String.format("%06d", props.numRequests);

			start = props.start;
			responseTime = props.random
					.nextInt(props.maxTransactionResponseTime.get(1) - props.maxTransactionResponseTime.get(0))
					+ props.maxTransactionResponseTime.get(0) + 1;

			int x = props.random.nextInt(props.issuerProduct.size());
			bin = props.issuerProduct.get(x).split(":")[0];
			issuer = props.issuerProduct.get(x).split(":")[1];
			product = props.issuerProduct.get(x).split(":")[2];
			hostIp= props.serverIp.get(x).split(":")[0];
			if (props.logDocuments) {
				LOGGER.info(":::");
				LOGGER.info("::: YRMONTH:  " + yearMonth);
				LOGGER.info("::: DAY:      " + day);
				LOGGER.info("::: MTI REQ:  " + mtiRequest);
				LOGGER.info("::: MTI RES:  " + mtiResponse);
				LOGGER.info("::: RESPCODE: " + responseCode);
				LOGGER.info("::: KEY:      " + key);
				LOGGER.info("::: TYPE:     " + type);
				LOGGER.info("::: START:    " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSSS").format(start));
				LOGGER.info("::: RESPTIME: " + responseTime);
				LOGGER.info("::: BIN:      " + bin);
				LOGGER.info("::: ISSUER:   " + issuer);
				LOGGER.info("::: PRODUCT:  " + product);
				LOGGER.info("::: PRODUCT:  " + hostIp);
				LOGGER.info(":::");
			}
		}
	}

	private final static Logger LOGGER = Logger.getLogger("correlacionador.simulador.Simulador");
	Props props;

	public static void main(String[] args) throws Exception {
		LOGGER.setLevel(Level.INFO);
		new Generator().doTheDo();
	}

	private void doTheDo() throws Exception {

		props = new Props();
		props.setNextEvent(-1);

		while (true) {

			props.start = System.currentTimeMillis();
			String yearMonth = new SimpleDateFormat("yyyyMM").format(new Date(props.start));
			if (yearMonth.equals(props.yearMonthPrev)) ;
			else {
				props.yearMonthPrev = yearMonth;
				doCreateIndex(yearMonth);
			}

			props.numRequests++;
			doReport();
			doStartStopIncident();
			Msg msg = new Msg();
			doStoreDocument(msg);
			int interval = props.random
					.nextInt(props.maxIntervalBetweenRquests.get(1) - props.maxIntervalBetweenRquests.get(0))
					+ props.maxIntervalBetweenRquests.get(0) + 1;
			Thread.sleep(interval);
		}
	}

	private void doReport() {
		if (props.numRequests % 1000 == 0) ;
		else return;
		LOGGER.info("::: " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date()) + ": "
				+ new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date(props.start)) + ": "
				+ props.numRequests);
	}

	private void doStartStopIncident() throws InterruptedException {

		if (props.incidentStarted == -1) {
			if (props.numRequests % props.nextNonResponseRequest == 0) {
				if (props.nonResponseRequestEvery.get(3) == 1) {
					props.incidentStarted = 2;
					props.incidentCount = 0;
				}
			} else if (props.numRequests % props.nextNotHonoredResponseCode == 0) {
				if (props.notHonoredResponseCodeEvery.get(3) == 1) {
					props.incidentStarted = 3;
					props.incidentCount = 0;
				}
			} else if (props.numRequests % props.nextSuspiciousResponseCode == 0) {
				if (props.suspiciousResponseCodeEvery.get(3) == 1) {
					props.incidentStarted = 4;
					props.incidentCount = 0;
				}
			} else if (props.numRequests % props.nextDeclinedResponseCode == 0) {
				if (props.declinedResponseCodeEvery.get(3) == 1) {
					props.incidentStarted = 5;
					props.incidentCount = 0;
				}
			}
		} else {

			switch (props.incidentStarted) {
			case -1:
				break;
			case 2:
				if (props.incidentCount > props.nonResponseRequestEvery.get(2)) {
					props.incidentStarted = -1;
					props.setNextEvent(2);
				}
				break;
			case 3:
				if (props.incidentCount > props.notHonoredResponseCodeEvery.get(2)) {
					props.incidentStarted = -1;
					props.setNextEvent(3);
				}
				break;
			case 4:
				if (props.incidentCount > props.suspiciousResponseCodeEvery.get(2)) {
					props.incidentStarted = -1;
					props.setNextEvent(4);
				}
				break;
			case 5:
				if (props.incidentCount > props.declinedResponseCodeEvery.get(2)) {
					props.incidentStarted = -1;
					props.setNextEvent(5);
				}
				break;
			default:
				LOGGER.info("::: ErrorCraso: IncidentStarted invalid: " + props.incidentStarted);
				break;
			}
		}
	}

	public void doCreateIndex(String yearMonth) throws IOException {
		props.indexName = "test_auth_" + yearMonth;
		GetIndexRequest indexRequest = new GetIndexRequest();
		indexRequest.indices(props.indexName);
		if (props.client.indices().exists(indexRequest, RequestOptions.DEFAULT)) ;
		else {
			CreateIndexRequest createIndexRequest = new CreateIndexRequest(props.indexName);
			XContentBuilder builder = XContentFactory.jsonBuilder();
			builder.startObject();
            {
                builder.startObject("properties");
                {
                    builder.startObject("@timestamp");
                    {
                        builder.field("type", "date");
                    }
                    builder.endObject();
                    builder.startObject("response_time");
                    {
                        builder.field("type", "integer");
                    }
                    builder.endObject();

                    builder.startObject("user");
                    {
                        builder.field("type", "keyword");
                    }
                    builder.endObject();

                    builder.startObject("product");
                    {
                        builder.field("type", "keyword");
                    }
                    builder.endObject();

                    builder.startObject("host");
                    {
                        builder.field("type", "ip");
                    }
                    builder.endObject();
                }
                builder.endObject();

            }
            builder.endObject();
			createIndexRequest.mapping("_doc", builder);
			props.client.indices().create(createIndexRequest, RequestOptions.DEFAULT);
			LOGGER.info("::: Index creado " + yearMonth);
		}
	}

	private void doStoreDocument(Msg msg) throws IOException {
		XContentBuilder builder = XContentFactory.jsonBuilder();
		builder.startObject();
		{
            builder.field("@timestamp", new Date());
			builder.field("response_time", msg.responseTime);
			builder.field("user", msg.bin);
			builder.field("product", msg.product);
			builder.field("host", msg.hostIp);
		}
		builder.endObject();
		IndexRequest request = new IndexRequest(props.indexName, "_doc", msg.key).source(builder);
		props.client.index(request, RequestOptions.DEFAULT);
	}

}
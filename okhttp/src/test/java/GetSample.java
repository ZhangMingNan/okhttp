import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class GetSample {
    public static void main(String[] args) {
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder().url("http://httpbin.org/ip").build();
        try (Response response = client.newCall(request).execute()) {
            System.out.println(response.body().string());
        } catch (Exception e) {
            System.out.println(e.getStackTrace());
        }

    }
}
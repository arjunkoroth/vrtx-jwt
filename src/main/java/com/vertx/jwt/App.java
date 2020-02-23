package com.vertx.jwt;

import com.vertx.jwt.controller.LoginController;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.http.HttpServer;
import io.vertx.ext.auth.KeyStoreOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.web.Router;

/**
 * Main Verticle.
 * 
 * @author Arjun.K
 *
 */
public class App extends AbstractVerticle {
	@Override
	public void start(Future<Void> startFuture) throws Exception {
		JWTAuthOptions config = new JWTAuthOptions()
				.setKeyStore(new KeyStoreOptions().setPath("keystore.jceks").setPassword("secret"));
		JWTAuth provider = JWTAuth.create(vertx, config);
		Router router = Router.router(vertx);
		LoginController loginController = new LoginController(vertx, provider);
		router.post("/api/login").handler(loginController::login);
		router.post("/api/checkToken").handler(loginController::checkToken);
		HttpServer server = vertx.createHttpServer();
		server.requestHandler(router::accept).listen(8084, "localhost", result -> {
			if (result.succeeded()) {
				startFuture.complete();
			} else {
				startFuture.fail(result.cause());
			}
		});
	}

}

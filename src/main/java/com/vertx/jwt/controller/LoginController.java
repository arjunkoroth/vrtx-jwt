package com.vertx.jwt.controller;

import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTOptions;
import io.vertx.ext.web.RoutingContext;

public class LoginController {
	Vertx vertx;
	JWTAuth provider;

	public LoginController(Vertx vertx, JWTAuth provider) {
		this.vertx = vertx;
		this.provider = provider;
	}
	
	/**
	 * This method is used to validate the user against the user details
	 * stored in the database. Generates JWT token if the user is valid.
	 * @param context
	 * @return generated base64 encoded JWT token.
	 * @author Arjun.K
	 */
	public void login(RoutingContext context) {
		try {
			context.request().bodyHandler(handler -> {
				JsonObject body = handler.toJsonObject();
				String username = body.getString("username");
				String password = body.getString("password");
				if (username.equals("admin") && password.equals("admin")) {
					String token = provider.generateToken(new JsonObject().put("username", username), 
							new JWTOptions().setExpiresInSeconds(60));
					render(context, 200, Buffer.buffer(new JsonObject().put("statusCode", 200).put("token", token).toString()), "application/json");
				} else {
					render(context, 404, Buffer.buffer(new JsonObject().put("statusCode", 404).put("message", "User not found").toString()), "application/json");
				}
			});
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * A test method to validate the JWT token from the request header.
	 * @param context
	 * @author Arjun.K
	 */
	public void checkToken(RoutingContext context) {
		try {
			String token = context.request().getHeader("x-api-key");
			provider.authenticate(new JsonObject().put("jwt", token), result -> {
				if (result.succeeded()) {
					User user = result.result();
					JsonObject object = user.principal();
					if (object.getString("username").equals("admin")) {
						render(context, 200, Buffer.buffer(new JsonObject().put("statusCode", 200).put("message", "Authorized user").toString()), "application/json");
					} else {
						render(context, 401, Buffer.buffer(new JsonObject().put("statusCode", 401).put("message", "Unauthorized user").toString()), "application/json");
					}
				}else {
					render(context, 401, Buffer.buffer(new JsonObject().put("statusCode", 401).put("message", "Unauthorized user").toString()), "application/json");
				}
			});
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Method used to create http response.
	 * @param context
	 * @param statusCode
	 * @param buffer
	 * @param contentType
	 * @author Arjun.K
	 */
	public static void render(RoutingContext context, int statusCode, Buffer buffer, String contentType) {
		if (context.response().closed()) {
			return;
		}
		context.response().setChunked(!context.response().headers().contains(HttpHeaders.CONTENT_LENGTH))
				.setStatusCode(statusCode);

		if (contentType != null) {
			context.response().putHeader(HttpHeaders.CONTENT_TYPE, contentType);
		}

		context.response().write(buffer).end();
	}
}

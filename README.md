# SpringSecurityHandsOnPractice
Spring Security Hands On Practice

1. Spring security Project Module: 
	- https://docs.spring.io/spring-security/reference/modules.html

2. Servlet Applications and security:
	- Spring Security integrates with the Servlet Container by using a standard Servlet Filter.
	- Architecture:
		- A Review of Filters: https://docs.spring.io/spring-security/reference/servlet/architecture.html
		- DelegatingFilterProxy:
			- DelegatingFilterProxy looks up Bean Filter from the ApplicationContext and then invokes Bean Filter.
			- You can register DelegatingFilterProxy through the standard Servlet container mechanisms but delegate all the work to a Spring Bean that implements Filter.
		- FilterChainProxy:
			- FilterChainProxy is registering directly with the Servlet container or DelegatingFilterProxy.
			- Since FilterChainProxy is a Bean, it is typically wrapped in a DelegatingFilterProxy.
			- It provides a starting point for all of Spring Security’s Servlet support.
			- It can perform tasks like clears out the SecurityContext to avoid memory leaks. It also applies Spring Security’s HttpFirewall to protect applications against certain types of attacks.
			- It provides more flexibility in determining when a SecurityFilterChain should be invoked.
			- FilterChainProxy can determine Filter instances invocation based upon anything in the HttpServletRequest by using the RequestMatcher interface.
			- FilterChainProxy is a special Filter provided by Spring Security that allows delegating to many Filter instances through SecurityFilterChain.			
			- SecurityFilterChain is used by FilterChainProxy to determine which Spring Security Filter instances should be invoked for the current request.
		- SecurityFilterChain:
			- The Security Filters in SecurityFilterChain are typically Beans, but they are registered with FilterChainProxy instead of DelegatingFilterProxy.
			- The Security Filters are inserted into the FilterChainProxy with the SecurityFilterChain API. 
			- Those filters can be used for a number of different purposes, like authentication, authorization, exploit protection, and more. The below configuration will result in the following Filter ordering:
			  CsrfFilter, UsernamePasswordAuthenticationFilter,BasicAuthenticationFilter, AuthorizationFilter
				@Configuration
				@EnableWebSecurity
				public class SecurityConfig {
					@Bean
					public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
						http
							.csrf(Customizer.withDefaults())
							.authorizeHttpRequests(authorize -> authorize
								.anyRequest().authenticated()
							)
							.httpBasic(Customizer.withDefaults())
							.formLogin(Customizer.withDefaults());
						return http.build();
					}
				}
		- Adding a Custom Filter to the Filter Chain:
			- Don't declare your custom filter as bean because of following reason:
			- Be careful when you declare your filter as a Spring bean, either by annotating it with @Component or by declaring it as a bean in your configuration, because Spring Boot will automatically register it with the embedded container. 
			- That may cause the filter to be invoked twice, once by the container and once by Spring Security and in a different order.
		- Handling Security Exceptions:
			- The ExceptionTranslationFilter allows translation of AccessDeniedException and AuthenticationException into HTTP responses.	
			- ExceptionTranslationFilter is inserted into the FilterChainProxy as one of the Security Filters.
			- Steps for exception filter:
				- i)First, the ExceptionTranslationFilter invokes FilterChain.doFilter(request, response) to invoke the rest of the application.
				- ii)If the user is not authenticated or it is an AuthenticationException, then Start Authentication.
					- The SecurityContextHolder is cleared out.
					- The HttpServletRequest is saved so that it can be used to replay the original request once authentication is successful.
					- The AuthenticationEntryPoint is used to request credentials from the client. For example, it might redirect to a log in page or send a WWW-Authenticate header.
				- iii)Otherwise, if it is an AccessDeniedException, then Access Denied. The AccessDeniedHandler is invoked to handle access denied.
			- If the application does not throw an AccessDeniedException or an AuthenticationException, then ExceptionTranslationFilter does not do anything.
		- Saving Requests Between Authentication:
			- when a request has no authentication and is for a resource that requires authentication, there is a need to save the request for the authenticated resource to re-request after authentication is successful. 
			- RequestCache:
				- This is done by saving the HttpServletRequest in the RequestCache. When the user successfully authenticates, the RequestCache is used to replay the original request.
				- The RequestCacheAwareFilter is what uses the RequestCache to save the HttpServletRequest.
				- By default, an HttpSessionRequestCache is used.
				- RequestCache Only Checks for Saved Requests if continue Parameter Present
					@Bean
					DefaultSecurityFilterChain springSecurity(HttpSecurity http) throws Exception {
						HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
						requestCache.setMatchingRequestParameterName("continue");
						http
							// ...
							.requestCache((cache) -> cache
								.requestCache(requestCache)
							);
						return http.build();
					}
		- Prevent the Request From Being Saved:
			- There are a number of reasons you may want to not store the user’s unauthenticated request in the session. To do that, you can use the NullRequestCache implementation.
		- Logging:
			- Spring Security provides comprehensive logging of all security related events at the DEBUG and TRACE level.
			- application.properties in Spring Boot
				logging.level.org.springframework.security=TRACE

3. Authentication:
	- Servlet Authentication Architecture: https://docs.spring.io/spring-security/reference/servlet/authentication/architecture.html
		- SecurityContextHolder - The SecurityContextHolder is where Spring Security stores the details of who is authenticated.
		- SecurityContext - is obtained from the SecurityContextHolder and contains the Authentication of the currently authenticated user.
		- Authentication - Can be the input to AuthenticationManager to provide the credentials a user has provided to authenticate or the current user from the SecurityContext.
		- GrantedAuthority - An authority that is granted to the principal on the Authentication (i.e. roles, scopes, etc.)
		- AuthenticationManager - the API that defines how Spring Security’s Filters perform authentication.
		- ProviderManager - the most common implementation of AuthenticationManager.
		- AuthenticationProvider - used by ProviderManager to perform a specific type of authentication.
		- Request Credentials with AuthenticationEntryPoint - used for requesting credentials from a client (i.e. redirecting to a log in page, sending a WWW-Authenticate response, etc.)
		- AbstractAuthenticationProcessingFilter - a base Filter used for authentication. This also gives a good idea of the high level flow of authentication and how pieces work together.
	
	- Username/Password Authentication:
		- Reading the Username & Password: Spring Security provides the following built-in mechanisms for reading a username and password from HttpServletRequest:
			- Form: https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/form.html
			- Basic: https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/basic.html
			- Digest: https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/digest.html
		- Storage Mechanisms:
			- Simple Storage with In-Memory Authentication: https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/in-memory.html
			- Relational Databases with JDBC Authentication: https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/jdbc.html
			- Custom data stores with UserDetailsService: https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/user-details-service.html
			- LDAP storage with LDAP Authentication: https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/ldap.html
	- Persisting Authentication: 
		- SecurityContextRepository: In Spring Security the association of the user to future requests is made using SecurityContextRepository. The default implementation of SecurityContextRepository is DelegatingSecurityContextRepository which delegates to the following:
			- HttpSessionSecurityContextRepository: it associates the SecurityContext to the HttpSession. 
			- RequestAttributeSecurityContextRepository: saves the SecurityContext as a request attribute to make sure the SecurityContext is available for a single request that occurs across dispatch types that may clear out the SecurityContext.
			- NullSecurityContextRepository: If it is not desirable to associate the SecurityContext to an HttpSession the NullSecurityContextRepository is an implementation of SecurityContextRepository that does nothing.
			- DelegatingSecurityContextRepository: The DelegatingSecurityContextRepository saves the SecurityContext to multiple SecurityContextRepository delegates and allows retrieval from any of the delegates in a specified order.
		- SecurityContextPersistenceFilter: It is responsible for persisting the SecurityContext between requests using the SecurityContextRepository.
			- a)Before running the rest of the application, SecurityContextPersistenceFilter loads the SecurityContext from the SecurityContextRepository and sets it on the SecurityContextHolder.
			- b)Next, the application is ran.
			- c)Finally, if the SecurityContext has changed, we save the SecurityContext using the SecurityContextPersistenceRepository. This means that when using SecurityContextPersistenceFilter, just setting the SecurityContextHolder will ensure that the SecurityContext is persisted using SecurityContextRepository.
		- SecurityContextHolderFilter:
			- a) Before running the rest of the application, SecurityContextHolderFilter loads the SecurityContext from the SecurityContextRepository and sets it on the SecurityContextHolder.
			- b) Next, the application is ran.
			- Unlike, SecurityContextPersistenceFilter, SecurityContextHolderFilter only loads the SecurityContext it does not save the SecurityContext. This means that when using SecurityContextHolderFilter, it is required that the SecurityContext is explicitly saved.
	- Authentication Persistence and Session Management:
		-  Understand Session Management’s components:
			- Understanding Session Management’s Components: The Session Management support is composed of a few components that work together-
				- SecurityContextHolderFilter
				- SecurityContextPersistenceFilter 
				- SessionManagementFilter
			- Customizing Where the Authentication Is Stored:
				- By default, Spring Security stores the security context for you in the HTTP session. However, here are several reasons you may want to customize that:
					- You may want call individual setters on the HttpSessionSecurityContextRepository instance
					- You may want to store the security context in a cache or database to enable horizontal scaling					
					- First, you need to create an implementation of SecurityContextRepository or use an existing implementation like HttpSessionSecurityContextRepository, then you can set it in HttpSecurity.
				- Storing the Authentication manually: https://docs.spring.io/spring-security/reference/servlet/authentication/session-management.html#how-it-works-requireexplicitsave
			- Configuring Persistence for Stateless Authentication:
				- Sometimes there is no need to create and maintain a HttpSession for example, Some authentication mechanisms like HTTP Basic are stateless and, therefore, re-authenticates the user on every request.
				- If you do not wish to create sessions, you can use SessionCreationPolicy.STATELESS, like so:
					@Bean
					public SecurityFilterChain filterChain(HttpSecurity http) {
						http
							// ...
							.sessionManagement((session) -> session
								.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
							);
						return http.build();
					}
				- The above configuration is configuring the SecurityContextRepository to use a NullSecurityContextRepository and is also preventing the request from being saved in the session.
			- Storing Stateless Authentication in the Session:
				- If, for some reason, you are using a stateless authentication mechanism, but you still want to store the authentication in the session you can use the HttpSessionSecurityContextRepository instead of the NullSecurityContextRepository.
		- Understanding Require Explicit Save:
			- the SecurityContextPersistenceFilter has been deprecated to be replaced with the SecurityContextHolderFilter. 
			- In Spring Security 6, the default behavior is that the SecurityContextHolderFilter will only read the SecurityContext from SecurityContextRepository and populate it in the SecurityContextHolder. 
			- Users now must explicitly save the SecurityContext with the SecurityContextRepository if they want the SecurityContext to persist between requests.
			-  This removes ambiguity and improves performance by only requiring writing to the SecurityContextRepository (i.e. HttpSession) when it is necessary.
			- How it works: when requireExplicitSave is true, Spring Security sets up the SecurityContextHolderFilter instead of the SecurityContextPersistenceFilter
		- Configuring Concurrent Session Control: https://docs.spring.io/spring-security/reference/servlet/authentication/session-management.html#ns-concurrent-sessions
		- Detecting Timeouts: 
			- Spring Security can detect when a session has expired and take specific actions that you indicate. 
			- For example, you may want to redirect to a specific endpoint when a user makes a request with an already-expired session. This is achieved through the invalidSessionUrl in HttpSecurity.
		- Customizing the Invalid Session Strategy: 
			- If you want to customize the behavior, you can implement the InvalidSessionStrategy interface and configure it using the invalidSessionStrategy method.
		- Clearing Session Cookies on Logout:
			- You can explicitly delete the JSESSIONID cookie on logging out: https://docs.spring.io/spring-security/reference/servlet/authentication/session-management.html#clearing-session-cookie-on-logout
		- Understanding Session Fixation Attack Protection: 
			- In this attacker to create a session by accessing a site, then persuade another user to log in with the same session (by sending them a link containing the session identifier as a parameter, for example). 
			- Spring Security protects against this automatically by creating a new session or otherwise changing the session ID when a user logs in.
			- Configuring Session Fixation Protection:
				- changeSessionId - Do not create a new session. Instead, use the session fixation protection provided by the Servlet container (HttpServletRequest#changeSessionId()).
				- newSession - Create a new "clean" session, without copying the existing session data.
				- migrateSession - Create a new session and copy all existing session attributes to the new session. 
		- Forcing Eager Session Creation: https://docs.spring.io/spring-security/reference/servlet/authentication/session-management.html#session-mgmt-force-session-creation
	
	- Remember-Me Authentication:
		- It refers to web sites being able to remember the identity of a principal between sessions. 
		- This is typically accomplished by sending a cookie to the browser, with the cookie being detected during future sessions and causing automated login to take place.
		- Spring security provides two concrete remember-me implementations.
			- Simple Hash-Based Token Approach: https://docs.spring.io/spring-security/reference/servlet/authentication/rememberme.html#remember-me-hash-token
			- Persistent Token Approach: https://docs.spring.io/spring-security/reference/servlet/authentication/rememberme.html#remember-me-persistent-token
		- Remember-Me Interfaces and Implementations:
			- Remember-me is used with UsernamePasswordAuthenticationFilter and BasicAuthenticationFilter. The hooks invoke a concrete RememberMeServices at the appropriate times. The following listing shows the interface:
			- TokenBasedRememberMeServices: https://docs.spring.io/spring-security/reference/servlet/authentication/rememberme.html#_tokenbasedremembermeservices
			- PersistentTokenBasedRememberMeServices: You can use this class in the same way as TokenBasedRememberMeServices, but it additionally needs to be configured with a PersistentTokenRepository to store the tokens.
				- InMemoryTokenRepositoryImpl which is intended for testing only.
				- JdbcTokenRepositoryImpl which stores the tokens in a database.
				
	- Java Authentication and Authorization Service (JAAS) Provider: https://docs.spring.io/spring-security/reference/servlet/authentication/jaas.html
	- CAS:
	- X.509:
	
	- Logout: 
		- Spring Security will add its logout support and by default respond both to GET /logout and POST /logout. If you request GET /logout, then Spring Security displays a logout confirmation page. 
		- If you request POST /logout, then it will perform the following default operations using a series of LogoutHandlers:
			- Invalidate the HTTP session (SecurityContextLogoutHandler)
			- Clear the SecurityContextHolderStrategy (SecurityContextLogoutHandler)
			- Clear the SecurityContextRepository (SecurityContextLogoutHandler)
			- Clean up any RememberMe authentication (TokenRememberMeServices / PersistentTokenRememberMeServices)
			- Clear out any saved CSRF token (CsrfLogoutHandler)
			- Fire a LogoutSuccessEvent (LogoutSuccessEventPublishingLogoutHandler)
			- Once completed, then it will exercise its default LogoutSuccessHandler which redirects to /login?logout.
		- Customizing Logout URIs: https://docs.spring.io/spring-security/reference/servlet/authentication/logout.html#customizing-logout-uris
			- Since the LogoutFilter appears before the AuthorizationFilter in the filter chain, it is not necessary by default to explicitly permit the /logout endpoint. 
			- Thus, only custom logout endpoints that you create yourself generally require a permitAll configuration to be reachable.
		- Adding Clean-up Actions:
			- Using Clear-Site-Data to Log Out the User: https://docs.spring.io/spring-security/reference/servlet/authentication/logout.html#clear-all-site-data
				- The Clear-Site-Data HTTP header is one that browsers support as an instruction to clear cookies, storage, and cache that belong to the owning website. This is a handy and secure way to ensure that everything, including the session cookie, is cleaned up on logout.
		- Customizing Logout Success: https://docs.spring.io/spring-security/reference/servlet/authentication/logout.html#customizing-logout-success
		- Creating a Custom Logout Endpoint:
	- Authentication Events: https://docs.spring.io/spring-security/reference/servlet/authentication/events.html
		- For each authentication that succeeds or fails, a AuthenticationSuccessEvent or AuthenticationFailureEvent, respectively, is fired.
		- To listen for these events, you must first publish an AuthenticationEventPublisher. Spring Security’s DefaultAuthenticationEventPublisher works fine for this purpose:
		
4. Authorization:
	- Authorization Architecture:
		- Authorities: 
			- Authentication implementations store a list of GrantedAuthority objects. 
			- These represent the authorities that have been granted to the principal. 
			- The GrantedAuthority objects are inserted into the Authentication object by the AuthenticationManager and are later read by AccessDecisionManager instances when making authorization decisions.
			- The GrantedAuthority interface has only one method: String getAuthority();
			- This method is used by an AuthorizationManager instance to obtain a precise String representation of the GrantedAuthority.
			- Spring Security includes one concrete GrantedAuthority implementation: SimpleGrantedAuthority. 
			- All AuthenticationProvider instances included with the security architecture use SimpleGrantedAuthority to populate the Authentication object.
			- By default, role-based authorization rules include ROLE_ as a prefix.
		- Invocation Handling (methos invocation or web request): 
			- Spring Security provides interceptors that control access to method invocations or web requests.
			- A pre-invocation decision is made by AuthorizationManager instances or a decisions on whether a given value may be returned is made by AuthorizationManager instances.
			- The AuthorizationManager: 
				- AuthorizationManagers are called by Spring Security’s request-based, method-based, and message-based authorization components.
				- Delegate-based AuthorizationManager Implementations: https://docs.spring.io/spring-security/reference/servlet/authorization/architecture.html#authz-delegate-authorization-manager
		- Adapting AccessDecisionManager and AccessDecisionVoters:
			- please check link: https://docs.spring.io/spring-security/reference/servlet/authorization/architecture.html#authz-voter-adaptation
		- Hierarchical Roles:
	- Authorize HttpServletRequests:
		- Understanding How Request Authorization Components Work:
			i) First, the AuthorizationFilter constructs a Supplier that retrieves an Authentication from the SecurityContextHolder.
			ii)Second, it passes the Supplier<Authentication> and the HttpServletRequest to the AuthorizationManager. The AuthorizationManager matches the request to the patterns in authorizeHttpRequests, and runs the corresponding rule.
			iii) If authorization is denied, an AuthorizationDeniedEvent is published, and an AccessDeniedException is thrown. In this case the ExceptionTranslationFilter handles the AccessDeniedException.
			iv) If access is granted, an AuthorizationGrantedEvent is published and AuthorizationFilter continues with the FilterChain which allows the application to process normally.
			- AuthorizationFilter Is Last By Default
			- All Dispatches Are Authorized
			- Authentication Lookup is Deferred
		- Authorizing an Endpoint
		- Matching Requests:
			- Matching Using Ant
			- Matching Using Regular Expressions
			- Matching By Http Method
			- Matching By Dispatcher Type
			- Using an MvcRequestMatcher: if you map Spring MVC to a different servlet path, then you need to account for that in your security configuration. For example, if Spring MVC is mapped to /spring-mvc instead of / (the default), then you may have an endpoint like /spring-mvc/my/controller that you want to authorize.
			- Using a Custom Matcher
		- Authorizing Requests: https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html#authorize-requests
		- Security Matchers:
			- The RequestMatcher interface is used to determine if a request matches a given rule. We use securityMatchers to determine if a given HttpSecurity should be applied to a given request. 
			- https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html#security-matchers
	
	- Method Security:
		- Spring Security also supports method level security by annotating any @Configuration class with @EnableMethodSecurity.
		- Then, you are immediately able to annotate any Spring-managed class or method with @PreAuthorize, @PostAuthorize, @PreFilter, and @PostFilter to authorize method invocations, including the input parameters and return values.
		- @EnableGlobalMethodSecurity or <global-method-security/>, these are now deprecated.
		- Method Security is built using Spring AOP, 
		- How Method Security Works: https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html#method-security-architecture
			- Multiple Annotations Are Computed In Series
			- Repeated Annotations Are Not Supported
			- Each Annotation Has Its Own Pointcut
			- Each Annotation Has Its Own Method Interceptor:
				- For @PreAuthorize, Spring Security uses AuthenticationManagerBeforeMethodInterceptor#preAuthorize, which in turn uses PreAuthorizeAuthorizationManager
				- For @PostAuthorize, Spring Security uses AuthenticationManagerAfterMethodInterceptor#postAuthorize, which in turn uses PostAuthorizeAuthorizationManager
				- For @PreFilter, Spring Security uses PreFilterAuthorizationMethodInterceptor
				- For @PostFilter, Spring Security uses PostFilterAuthorizationMethodInterceptor
				- For @Secured, Spring Security uses AuthenticationManagerBeforeMethodInterceptor#secured, which in turn uses SecuredAuthorizationManager
				- For JSR-250 annotations, Spring Security uses AuthenticationManagerBeforeMethodInterceptor#jsr250, which in turn uses Jsr250AuthorizationManager
			- Comparing Request-level vs Method-level Authorization: https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html#request-vs-method
			- Authorizing with Annotations: Spring Security enables method-level authorization support is through annotations that you can add to methods, classes, and interfaces.
				- Authorizing Method Invocation with @PreAuthorize
				- Authorization Method Results with @PostAuthorize
				- Filtering Method Parameters with @PreFilter
				- Filtering Method Results with @PostFilter
				- Authorizing Method Invocation with @Secured: 
					- @Secured is a legacy option for authorizing invocations. @PreAuthorize supercedes it and is recommended instead.
				- Authorizing Method Invocation with JSR-250 Annotations
					- @EnableMethodSecurity(jsr250Enabled = true)
					- @RolesAllowed, @PermitAll, and @DenyAll
				- Declaring Annotations at the Class or Interface Level
				- Using Meta Annotations
				- Enabling Certain Annotations
			- Authorizing Methods Programmatically:
				- Using a Custom Bean in SpEL
				- Using a Custom Authorization Manager
				- Customizing Expression Handling
			- Authorizing with AspectJ
				- Matching Methods with Custom Pointcuts
				- Integrate with AspectJ Byte-weaving
			- Specifying Order:
				- Namely, the @PreFilter method interceptor’s order is 100, @PreAuthorize's is 200, and so on.
				- this is important because For example, if you have a method annotated with @Transactional and @PostAuthorize, you might want the transaction to still be open when @PostAuthorize runs so that an AccessDeniedException will cause a rollback.
			- Migrating from @EnableGlobalMethodSecurity
				- If you are using @EnableGlobalMethodSecurity, you should migrate to @EnableMethodSecurity.
				- Use a Custom @Bean instead of subclassing DefaultMethodSecurityExpressionHandler
				
5. Domain Object Security (ACLs): https://docs.spring.io/spring-security/reference/servlet/authorization/acls.html
			 
6. Authorization Events:
	- For each authorization that is denied, an AuthorizationDeniedEvent is fired. Also, it’s possible to fire and AuthorizationGrantedEvent for authorizations that are granted.
	- To listen for these events, you must first publish an AuthorizationEventPublisher.
	- Spring Security’s SpringAuthorizationEventPublisher will probably do fine. It comes publishes authorization events using Spring’s ApplicationEventPublisher:

7. OAuth2:
	- OAuth 2.0 Login: OAuth 2.0 Login is implemented by using the Authorization Code Grant.
		- Core Configuration:
			- Spring Boot 2.x brings full auto-configuration capabilities for OAuth 2.0 Login.
			- Initial Setup: 
				- To use Google’s OAuth 2.0 authentication system for login, you must set up a project in the Google API Console to obtain OAuth 2.0 credentials.
				- after completion you should have new oauth client with credentials consisting of client id and client secret.
			- Setting the Redirect URI: The redirect URI is the path in the application that the end-user’s user-agent is redirected back to after they have authenticated with Google and have granted access to the OAuth Client (created in the previous step) on the Consent page.
			- Configure application.yml: https://docs.spring.io/spring-security/reference/servlet/oauth2/login/core.html#oauth2login-sample-application-config
				- OAuth Client properties
					- spring.security.oauth2.client.registration.{registrationId} google is the base property prefix for OAuth Client properties. 
					- Following the base property prefix is the ID for the ClientRegistration, such as Google.

			- Boot up the Application:
				- Launch the Spring Boot 2.x sample and go to localhost:8080. 
				- You are then redirected to the default auto-generated login page, which displays a link for Google.
				- Click on the Google link, and you are then redirected to Google for authentication.
				- After authenticating with your Google account credentials, you see the Consent screen.
				- The Consent screen asks you to either allow or deny access to the OAuth Client you created earlier. Click Allow to authorize the OAuth Client to access your email address and basic profile information.
				- At this point, the OAuth Client retrieves your email address and basic profile information from the UserInfo Endpoint and establishes an authenticated session.
			- Spring Boot 2.x Property Mappings: https://docs.spring.io/spring-security/reference/servlet/oauth2/login/core.html#oauth2login-boot-property-mappings
			- CommonOAuth2Provider:
				- CommonOAuth2Provider pre-defines a set of default client properties for a number of well known providers: Google, GitHub, Facebook, and Okta.
				- The auto-defaulting of client properties works seamlessly here because the registrationId (google) matches the GOOGLE enum (case-insensitive) in CommonOAuth2Provider.
			- Overriding Spring Boot 2.x Auto-configuration
				- The Spring Boot 2.x auto-configuration class for OAuth Client support is OAuth2ClientAutoConfiguration.
				- It performs the following tasks:
					- Registers a ClientRegistrationRepository @Bean composed of ClientRegistration(s) from the configured OAuth Client properties.
					- Registers a SecurityFilterChain @Bean and enables OAuth 2.0 Login through httpSecurity.oauth2Login().
				- Register a ClientRegistrationRepository @Bean: https://docs.spring.io/spring-security/reference/servlet/oauth2/login/core.html#oauth2login-register-clientregistrationrepository-bean
				- Register a SecurityFilterChain @Bean: https://docs.spring.io/spring-security/reference/servlet/oauth2/login/core.html#oauth2login-provide-securityfilterchain-bean
				- Completely Override the Auto-configuration: https://docs.spring.io/spring-security/reference/servlet/oauth2/login/core.html#oauth2login-completely-override-autoconfiguration
			- Java Configuration without Spring Boot 2.x: https://docs.spring.io/spring-security/reference/servlet/oauth2/login/core.html#oauth2login-javaconfig-wo-boot
		- Advanced Configuration:
			- HttpSecurity.oauth2Login() provides a number of configuration options for customizing OAuth 2.0 Login. The main configuration options are grouped into their protocol endpoint counterparts.
				- HttpSecurity.oauth2Login().authorizationEndpoint
				- HttpSecurity.oauth2Login().redirectionEndpoint
				- HttpSecurity.oauth2Login().tokenEndpoint
				- HttpSecurity.oauth2Login().userInfoEndpoint
			- The following sections go into more detail on each of the configuration options available:
				- OAuth 2.0 Login Page: 
					- By default, the OAuth 2.0 Login Page is auto-generated by the DefaultLoginPageGeneratingFilter.
					- The default login page shows each configured OAuth Client with its ClientRegistration.clientName as a link
					- To override the default login page, configure oauth2Login().loginPage() and (optionally) oauth2Login().authorizationEndpoint().baseUri().					
				- Redirection Endpoint:
					- The Redirection Endpoint is used by the Authorization Server for returning the Authorization Response (which contains the authorization credentials) to the client through the Resource Owner user-agent.
				- UserInfo Endpoint
				- ID Token Signature Verification
				- OpenID Connect 1.0 Logout
			- ID Token Signature Verification:
				- OpenID Connect 1.0 Authentication introduces the ID Token, which is a security token that contains Claims about the Authentication of an End-User by an Authorization Server when used by a Client.
				- The ID Token is represented as a JSON Web Token (JWT) and MUST be signed by using JSON Web Signature (JWS).
	- OAuth 2.0 Client: At a high-level, the core features available are:
		- Authorization Grant support
			- Authorization Code
			- Refresh Token
			- Client Credentials
			- Resource Owner Password Credentials
			- JWT Bearer
		- Client Authentication support
			- JWT Bearer
		- HTTP Client support
			- WebClient integration for Servlet Environments (for requesting protected resources)
		- The HttpSecurity.oauth2Client() DSL provides a number of configuration options for customizing the core components used by OAuth 2.0 Client. 
		- In addition, HttpSecurity.oauth2Client().authorizationCodeGrant() enables the customization of the Authorization Code grant.
		- The OAuth2AuthorizedClientManager is responsible for managing the authorization (or re-authorization) of an OAuth 2.0 Client, in collaboration with one or more OAuth2AuthorizedClientProvider(s).
		- Core Interfaces and Classes:
			- https://docs.spring.io/spring-security/reference/servlet/oauth2/client/core.html
	- OAuth 2.0 Resource Server:
		- Spring Security supports protecting endpoints by using two forms of OAuth 2.0 Bearer Tokens:
			- JWT	
			- Opaque Tokens
		- This section details how Spring Security provides support for OAuth 2.0 Bearer Tokens.
		- check link: https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/index.html
		- OAuth 2.0 Resource Server JWT:
			- Minimal Dependencies for JWT: spring-security-oauth2-resource-server and spring-security-oauth2-jose
			- Minimal Configuration for JWT:
				- Specifying the Authorization Server
					- In a Spring Boot application, to specify which authorization server to use, simply do:
						spring.security.oauth2.resourceserver.jwt.issuer-uri: https://idp.example.com/issuer
					- Resource Server will use this property to further self-configure, discover the authorization server’s public keys, and subsequently validate incoming JWTs.
				- Startup Expectations: Query endpoint jwks_url for algoritham and public keys
				- Runtime Expectations: validate JWT public keys with the key received from jwks_url endpoint and check token expiry
			- How JWT Authentication Works: https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html#oauth2resourceserver-jwt-architecture
			- Overriding or Replacing Boot Auto Configuration: https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html#oauth2resourceserver-jwt-sansboot
		- OAuth 2.0 Resource Server Opaque Token:
			- Minimal Dependencies for Introspection
				- both spring-security-oauth2-resource-server and oauth2-oidc-sdk are necessary dependancies in order to have a working Resource Server that supports opaque Bearer Tokens.
			- Minimal Configuration for Introspection:
				- Specifying the Authorization Server: 
					- Typically, an opaque token can be verified via an OAuth 2.0 Introspection Endpoint, hosted by the authorization server. 
					- configuring an application as a resource server to support opaque token consists of two basic steps, First, include the needed dependencies and second, indicate the introspection endpoint details.
					- To specify where the introspection endpoint is, spring. security.oauth2.resourceserver.opaque-token.introspection-uri: https://idp.example.com/introspect, client-id: client, client-secret: secret
				- Startup Expectations: When this property and these dependencies are used, Resource Server will automatically configure itself to validate Opaque Bearer Tokens.
				- Runtime Expectations: Once the application is started up, Resource Server will attempt to process any request containing an Authorization: Bearer header:
			- How Opaque Token Authentication Works: https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/opaque-token.html#oauth2resourceserver-opaque-architecture
			- Overriding or Replacing Boot Auto Configuration: https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/opaque-token.html#oauth2resourceserver-opaque-sansboot
		- OAuth 2.0 Resource Server Multi-tenancy:
			- Supporting both JWT and Opaque Token:
				- you may support more than one tenant where one tenant issues JWTs and the other issues opaque tokens.
				- This decision must be made at request-time, then you can use an AuthenticationManagerResolver to achieve it, like so: https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/multitenancy.html
				- A resource server is considered multi-tenant when there are multiple strategies for verifying a bearer token, keyed by some tenant identifier.
				- For example, your resource server may accept bearer tokens from two different authorization servers. Or, your authorization server may represent a multiplicity of issuers.
				- In each case, there are two things that need to be done and trade-offs associated with how you choose to do them:
					- Resolve the tenant: One way to differentiate tenants is by the issuer claim. Since the issuer claim accompanies signed JWTs, this can be done with the JwtIssuerAuthenticationManagerResolver.
					- Propagate the tenant
		- OAuth 2.0 Bearer Tokens:
			- Bearer Token Resolution: By default, Resource Server looks for a bearer token in the Authorization header. This, however, can be customized in a handful of ways.
				- Reading the Bearer Token from a Custom Header: To achieve this, you can expose a DefaultBearerTokenResolver as a bean, or wire an instance into the DSL, as you see https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/bearer-tokens.html#_reading_the_bearer_token_from_a_custom_header
				- Bearer Token Propagation: Now that your resource server has validated the token, it might be handy to pass it to downstream services. This is quite simple with ServletBearerExchangeFilterFunction, which you can see in the following example:
				  https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/bearer-tokens.html#_bearer_token_propagation
				- Bearer Token Failure: A bearer token may be invalid for a number of reasons. In these circumstances, Resource Server throws an InvalidBearerTokenException. 
			
8. SAML2.0: https://docs.spring.io/spring-security/reference/servlet/saml2/index.html
	- SAML2 Log In
	- SAML2 Logout
	- SAML2 Metadata

				
9. Protection Against Exploits:
	- Cross Site Request Forgery (CSRF)
	- Security HTTP Response Headers
	- HTTP
	- HttpFirewall

10. Integrations: Spring Security integrates with numerous frameworks and APIs. This section describes various integrations that Spring Security has with other technologies:
Jackson
	-Concurrency
	-Localization
	-Servlet APIs
	-Spring Data
	-Spring MVC
	-WebSocket
	-Spring’s CORS Support
	-JSP Taglib
	-Observability	

11. Testing:

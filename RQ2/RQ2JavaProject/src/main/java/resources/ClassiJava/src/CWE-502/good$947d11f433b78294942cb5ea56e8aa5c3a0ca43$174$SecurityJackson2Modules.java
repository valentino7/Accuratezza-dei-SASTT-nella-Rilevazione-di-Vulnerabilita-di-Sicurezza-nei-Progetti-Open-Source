/*
 * Copyright 2015-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.jackson2;

import com.fasterxml.jackson.annotation.JacksonAnnotation;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.cfg.MapperConfig;
import com.fasterxml.jackson.databind.jsontype.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.util.ClassUtils;

import java.io.IOException;
import java.util.*;

/**
 * This utility class will find all the SecurityModules in classpath.
 *
 * <p>
 * <pre>
 *     ObjectMapper mapper = new ObjectMapper();
 *     mapper.registerModules(SecurityJackson2Modules.getModules());
 * </pre>
 * Above code is equivalent to
 * <p>
 * <pre>
 *     ObjectMapper mapper = new ObjectMapper();
 *     mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL, JsonTypeInfo.As.PROPERTY);
 *     mapper.registerModule(new CoreJackson2Module());
 *     mapper.registerModule(new CasJackson2Module());
 *     mapper.registerModule(new WebJackson2Module());
 * </pre>
 *
 * @author Jitendra Singh.
 * @since 4.2
 */
public final class SecurityJackson2Modules {

	private static final Log logger = LogFactory.getLog(SecurityJackson2Modules.class);
	private static final List<String> securityJackson2ModuleClasses = Arrays.asList(
			"org.springframework.security.jackson2.CoreJackson2Module",
			"org.springframework.security.cas.jackson2.CasJackson2Module",
			"org.springframework.security.web.jackson2.WebJackson2Module"
	);

	private SecurityJackson2Modules() {
	}

	public static void enableDefaultTyping(ObjectMapper mapper) {
		if(mapper != null) {
			TypeResolverBuilder<?> typeBuilder = mapper.getDeserializationConfig().getDefaultTyper(null);
			if (typeBuilder == null) {
				mapper.setDefaultTyping(createWhitelistedDefaultTyping());
			}
		}
	}

	@SuppressWarnings("unchecked")
	private static Module loadAndGetInstance(String className, ClassLoader loader) {
		Module instance = null;
		try {
			Class<? extends Module> securityModule = (Class<? extends Module>) ClassUtils.forName(className, loader);
			if (securityModule != null) {
				if(logger.isDebugEnabled()) {
					logger.debug("Loaded module " + className + ", now registering");
				}
				instance = securityModule.newInstance();
			}
		} catch (Exception e) {
			if(logger.isDebugEnabled()) {
				logger.debug("Cannot load module " + className, e);
			}
		}
		return instance;
	}

	/**
	 * @param loader the ClassLoader to use
	 * @return List of available security modules in classpath.
	 */
	public static List<Module> getModules(ClassLoader loader) {
		List<Module> modules = new ArrayList<Module>();
		for (String className : securityJackson2ModuleClasses) {
			Module module = loadAndGetInstance(className, loader);
			if (module != null) {
				modules.add(module);
			}
		}
		return modules;
	}

	/**
	 * Creates a TypeResolverBuilder that performs whitelisting.
	 * @return a TypeResolverBuilder that performs whitelisting.
	 */
	private static TypeResolverBuilder<? extends TypeResolverBuilder> createWhitelistedDefaultTyping() {
		TypeResolverBuilder<? extends TypeResolverBuilder>  result = new WhitelistTypeResolverBuilder(ObjectMapper.DefaultTyping.NON_FINAL);
		result = result.init(JsonTypeInfo.Id.CLASS, null);
		result = result.inclusion(JsonTypeInfo.As.PROPERTY);
		return result;
	}

	/**
	 * An implementation of {@link ObjectMapper.DefaultTypeResolverBuilder} that overrides the {@link TypeIdResolver}
	 * with {@link WhitelistTypeIdResolver}.
	 * @author Rob Winch
	 */
	static class WhitelistTypeResolverBuilder extends ObjectMapper.DefaultTypeResolverBuilder {

		public WhitelistTypeResolverBuilder(ObjectMapper.DefaultTyping defaultTyping) {
			super(defaultTyping);
		}

		protected TypeIdResolver idResolver(MapperConfig<?> config,
											JavaType baseType, Collection<NamedType> subtypes, boolean forSer, boolean forDeser) {
			TypeIdResolver result = super.idResolver(config, baseType, subtypes, forSer, forDeser);
			return new WhitelistTypeIdResolver(result);
		}
	}

	/**
	 * A {@link TypeIdResolver} that delegates to an existing implementation and throws an IllegalStateException if the
	 * class being looked up is not whitelisted, does not provide an explicit mixin, and is not annotated with Jackson
	 * mappings. See https://github.com/spring-projects/spring-security/issues/4370
	 */
	static class WhitelistTypeIdResolver implements TypeIdResolver {
		private static final Set<String> WHITELIST_CLASS_NAMES = Collections.unmodifiableSet(new HashSet(Arrays.asList(
			"java.util.ArrayList",
			"java.util.Collections$EmptyMap",
			"java.util.Date",
			"java.util.TreeMap",
			"org.springframework.security.core.context.SecurityContextImpl"
		)));

		private final TypeIdResolver delegate;

		WhitelistTypeIdResolver(TypeIdResolver delegate) {
			this.delegate = delegate;
		}

		@Override
		public void init(JavaType baseType) {
			delegate.init(baseType);
		}

		@Override
		public String idFromValue(Object value) {
			return delegate.idFromValue(value);
		}

		@Override
		public String idFromValueAndType(Object value, Class<?> suggestedType) {
			return delegate.idFromValueAndType(value, suggestedType);
		}

		@Override
		public String idFromBaseType() {
			return delegate.idFromBaseType();
		}

		@Override
		public JavaType typeFromId(DatabindContext context, String id) throws IOException {
			DeserializationConfig config = (DeserializationConfig) context.getConfig();
			JavaType result = delegate.typeFromId(context, id);
			String className = result.getRawClass().getName();
			if(isWhitelisted(className)) {
				return delegate.typeFromId(context, id);
			}
			boolean isExplicitMixin = config.findMixInClassFor(result.getRawClass()) != null;
			if(isExplicitMixin) {
				return result;
			}
			JacksonAnnotation jacksonAnnotation = AnnotationUtils.findAnnotation(result.getRawClass(), JacksonAnnotation.class);
			if(jacksonAnnotation != null) {
				return result;
			}
			throw new IllegalArgumentException("The class with " + id + " and name of " + className + " is not whitelisted. " +
				"If you believe this class is safe to deserialize, please provide an explicit mapping using Jackson annotations or by providing a Mixin. " +
				"If the serialization is only done by a trusted source, you can also enable default typing. " +
				"See https://github.com/spring-projects/spring-security/issues/4370 for details");
		}

		private boolean isWhitelisted(String id) {
			return WHITELIST_CLASS_NAMES.contains(id);
		}

		@Override
		public String getDescForKnownTypeIds() {
			return delegate.getDescForKnownTypeIds();
		}

		@Override
		public JsonTypeInfo.Id getMechanism() {
			return delegate.getMechanism();
		}

	}
}

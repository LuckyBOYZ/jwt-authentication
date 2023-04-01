package pl.lukaszsuma.jwtauthentication.config;

import lombok.SneakyThrows;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

@Component
record RSAKeysBeanFactory() implements BeanFactoryPostProcessor {

    @SneakyThrows
    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        KeyPairGenerator keys = KeyPairGenerator.getInstance("RSA");
        ByteBuffer bb = ByteBuffer.allocate(Long.BYTES);
        long value = System.currentTimeMillis();
        bb.putLong(value);
        byte[] array = bb.array();
        keys.initialize(2048, new SecureRandom(array));
        KeyPair kp = keys.generateKeyPair();
        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();

        byte[] encodePublic = Base64.getEncoder().encode(publicKey.getEncoded());
        String rawPublicKey = new String(encodePublic);
        String wholePublicKey = ("-----BEGIN PUBLIC KEY-----" + System.lineSeparator())
                .concat(rawPublicKey + System.lineSeparator()).concat("-----END PUBLIC KEY-----");

        byte[] encodePrivate = Base64.getEncoder().encode(privateKey.getEncoded());
        String rawPrivateKey = new String(encodePrivate);
        String wholePrivateKey = ("-----BEGIN PRIVATE KEY-----" + System.lineSeparator())
                .concat(rawPrivateKey + System.lineSeparator()).concat("-----END PRIVATE KEY-----");

        RSAPublicKey convertPublic = RsaKeyConverters.x509().convert(new ByteArrayInputStream(wholePublicKey.getBytes()));
        RSAPrivateKey convertPrivate = RsaKeyConverters.pkcs8().convert(new ByteArrayInputStream(wholePrivateKey.getBytes()));

        beanFactory.registerSingleton("rsaPublicKey", convertPublic);
        beanFactory.registerSingleton("rsaPrivateKey", convertPrivate);
    }
}

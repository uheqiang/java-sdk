# java-sdk
java sdk for Proxy re-encryption functionality

javac -classpath bcprov-jdk15on-154.jar Curve.java Scalar.java GroupElement.java PublicKey.java PrivateKey.java KeyPair.java ReEncryptionKey.java Capsule.java ProxyUtils.java Proxy.java

java -classpath bcprov-jdk15on-154.jar:. Proxy ProxyUtils Capsule ReEncriptionKey KeyPair PrivateKey Scalar Curve PublicKey GroupElement

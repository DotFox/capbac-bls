package dotfox.capbac;

import java.net.URI;
import java.util.Iterator;
import java.util.stream.StreamSupport;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import dotfox.capbac.CapBAC.Malformed;

public class CapBACCertificate implements Iterable<CapBACCertificate> {
    final CapBACProto.Certificate proto;
    final CapBACProto.Certificate.Payload payload;

    public static String DEFAULT_CONTENT_TYPE = "application/octet-stream";

    public static class Builder {
        URI subject;
        byte[] capability;
        long exp = 0;

        public Builder(URI subject, byte[] capability) {
            this.subject = subject;
            this.capability = capability;
        }

        public Builder withExp(long exp) {
            this.exp = exp;
            return this;
        }

        public Builder build() {
            return this;
        }
    }

    public CapBACCertificate(byte[] data) throws Malformed {
        try {
            this.proto = CapBACProto.Certificate.parseFrom(data);
            this.payload = CapBACProto.Certificate.Payload.parseFrom(proto.getPayload());
        } catch (InvalidProtocolBufferException e) {
            throw new Malformed(e);
        }
    }

    CapBACCertificate(CapBACProto.Certificate proto) throws Malformed {
        this.proto = proto;
        try {
            this.payload = CapBACProto.Certificate.Payload.parseFrom(proto.getPayload());
        } catch (InvalidProtocolBufferException e) {
            throw new Malformed(e);
        }
    }

    CapBACCertificate(CapBACProto.Certificate.Payload payload) {
        this.payload = payload;
        CapBACProto.Certificate.Builder protoBuilder = CapBACProto.Certificate.newBuilder();
        protoBuilder.setPayload(payload.toByteString());
        this.proto = protoBuilder.build();
    }

    CapBACCertificate(Builder builder, CapBACHolder signer) {
        this(null, builder, signer);
    }

    CapBACCertificate(CapBACCertificate parent, Builder builder, CapBACHolder signer) {
        CapBACProto.Certificate.Payload.Builder payloadBuilder = CapBACProto.Certificate.Payload.newBuilder();
        payloadBuilder.setCapability(ByteString.copyFrom(builder.capability));
        payloadBuilder.setExpiration(builder.exp);
        payloadBuilder.setSubject(builder.subject.toString());
        payloadBuilder.setIssuer(signer.me.toString());
        if (parent != null) {
            payloadBuilder.setParent(parent.payload);
        }

        CapBACProto.Certificate.Payload payload = payloadBuilder.build();
        ByteString payloadBytes = payload.toByteString();

        CapBACProto.Certificate.Builder protoBuilder = CapBACProto.Certificate.newBuilder();
        protoBuilder.setPayload(payloadBytes);
        protoBuilder.setSignature(ByteString.copyFrom(signer.sign(payloadBytes.toByteArray(), parent != null ? parent.getSignature() : null).getSignature().toBytes()));

        this.proto = protoBuilder.build();
        this.payload = payload;
    }

    public byte[] getCapability() {
        return payload.getCapability().toByteArray();
    }

    public byte[] getSignature() {
        return proto.getSignature().toByteArray();
    }

    public URI getIssuer() throws Malformed {
        try {
            return URI.create(payload.getIssuer());
        } catch (IllegalArgumentException | NullPointerException e) {
            throw new Malformed(e);
        }
    }

    public URI getSubject() throws Malformed {
        try {
            return URI.create(payload.getSubject());
        } catch (IllegalArgumentException | NullPointerException e) {
            throw new Malformed(e);
        }
    }

    public long getExpiration() {
        return payload.getExpiration();
    }

    public CapBACCertificate getParent() {
        if (payload.hasParent()) {
            return new CapBACCertificate(payload.getParent());
        } else {
            return null;
        }
    }

    public URI getRootIssuer() throws Malformed {
        return StreamSupport.stream(this.spliterator(), false).reduce((first, second) -> second).get().getIssuer();
    }

    public byte[] getPayloadBytes() {
        return payload.toByteArray();
    }

    public String getContentType() {
        String content_type;
        if ((content_type = payload.getContentType()) != null) {
            return content_type;
        } else {
            return DEFAULT_CONTENT_TYPE;
        }
    }

    @Override
    public Iterator<CapBACCertificate> iterator() {
        return new Iterator<CapBACCertificate>() {
            private CapBACCertificate next = CapBACCertificate.this;

            @Override
            public boolean hasNext() {
                return next != null;
            }

            @Override
            public CapBACCertificate next() {
                CapBACCertificate prev = next;
                next = prev.getParent();
                return prev;
            }
        };
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((payload == null) ? 0 : payload.hashCode());
        result = prime * result + ((proto == null) ? 0 : proto.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        CapBACCertificate other = (CapBACCertificate) obj;
        if (payload == null) {
            if (other.payload != null)
                return false;
        } else if (!payload.equals(other.payload))
            return false;
        if (proto == null) {
            if (other.proto != null)
                return false;
        } else if (!proto.equals(other.proto))
            return false;
        return true;
    }
}

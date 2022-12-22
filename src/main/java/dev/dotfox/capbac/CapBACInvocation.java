package dev.dotfox.capbac;

import java.net.URI;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

public class CapBACInvocation {
    final CapBACProto.Invocation proto;
    final CapBACProto.Invocation.Payload payload;

    public static String DEFAULT_CONTENT_TYPE = "application/octet-stream";

    public static class Builder {
        byte[] action;
        long exp = 0;

        public Builder(byte[] action) {
            this.action = action;
        }

        public Builder withExp(long exp) {
            this.exp = exp;
            return this;
        }
    }

    public CapBACInvocation(byte[] data) throws CapBAC.Malformed {
        try {
            this.proto = CapBACProto.Invocation.parseFrom(data);
            this.payload = CapBACProto.Invocation.Payload.parseFrom(proto.getPayload());
        } catch (InvalidProtocolBufferException e) {
            throw new CapBAC.Malformed(e);
        }
    }

    CapBACInvocation(CapBACCertificate certificate, Builder builder, CapBACHolder signer) {
        CapBACProto.Invocation.Payload.Builder payloadBuilder = CapBACProto.Invocation.Payload.newBuilder();
        payloadBuilder.setAction(ByteString.copyFrom(builder.action));
        payloadBuilder.setInvoker(signer.me.toString());
        payloadBuilder.setCertificate(certificate.payload);
        payloadBuilder.setExpiration(builder.exp);

        CapBACProto.Invocation.Payload payload = payloadBuilder.build();
        ByteString payloadBytes = payload.toByteString();

        CapBACProto.Invocation.Builder protoBuilder = CapBACProto.Invocation.newBuilder();
        protoBuilder.setPayload(payloadBytes);
        protoBuilder.setSignature(ByteString.copyFrom(signer.sign(payloadBytes.toByteArray(), certificate.getSignature()).getSignature().toBytes()));

        this.proto = protoBuilder.build();
        this.payload = payload;
    }

    public byte[] getAction() {
        return payload.getAction().toByteArray();
    }

    public byte[] getSignature() {
        return proto.getSignature().toByteArray();
    }

    public URI getInvoker() throws CapBAC.Malformed {
        try {
            return URI.create(payload.getInvoker());
        } catch (IllegalArgumentException | NullPointerException e) {
            throw new CapBAC.Malformed(e);
        }
    }

    public long getExpiration() {
        return payload.getExpiration();
    }

    public CapBACCertificate getCertificate() {
        return new CapBACCertificate(payload.getCertificate());
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
        CapBACInvocation other = (CapBACInvocation) obj;
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

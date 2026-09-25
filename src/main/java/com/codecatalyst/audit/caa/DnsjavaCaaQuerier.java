/*
 * Copyright (c) 2026 CodeCatalyst
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.codecatalyst.audit.caa;

import org.xbill.DNS.*;
import org.xbill.DNS.Record;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Real CAA queries through dnsjava. Uses {@code SimpleResolver.send} rather than {@code Lookup}
 * because only the raw response exposes the AD bit (D8 F11). The resolver follows CNAMEs itself and
 * returns the chain plus the target's records, so every CAA record in the answer is taken whatever
 * owner name the chain ends at.
 */
public class DnsjavaCaaQuerier implements CaaQuerier {

    private final SimpleResolver resolver;

    public DnsjavaCaaQuerier(String resolverAddress) throws IOException {
        this.resolver = new SimpleResolver(resolverAddress);
        this.resolver.setTimeout(Duration.ofSeconds(5));
    }

    @Override
    public CaaAnswer query(String name) throws IOException {
        Record question = Record.newRecord(Name.fromString(name.endsWith(".") ? name : name + "."), Type.CAA, DClass.IN);
        Message query = Message.newQuery(question);
        query.getHeader().setFlag(Flags.AD); // RFC 6840 §5.7: ask the resolver to report validation status
        Message resp = resolver.send(query);
        List<CaaProperty> props = new ArrayList<>();
        for (Record r : resp.getSection(Section.ANSWER)) {
            if (r instanceof CAARecord caa) {
                props.add(new CaaProperty(caa.getFlags(), caa.getTag(), caa.getValue()));
            }
        }
        return new CaaAnswer(resp.getRcode(), Rcode.string(resp.getRcode()),
                resp.getHeader().getFlag(Flags.AD), props);
    }
}

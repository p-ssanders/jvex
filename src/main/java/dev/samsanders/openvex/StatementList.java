package dev.samsanders.openvex;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collection;

/**
 * This list preserves integrity of existing Statements
 * by ensuring the existing Statements without timestamps inherit the Document's timestamp
 * and by updating the Document's timestamp to now
 * @see <a href="https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#data-inheritance">Data Inheritance</a>
 */
class StatementList<E> extends ArrayList<E> {
    private final Document document;

    StatementList(Collection<? extends E> list, Document document) {
        super(list);
        this.document = document;
    }

    @Override
    public boolean add(E e) {
        for (Statement s : document.getStatements()) {
            if (null == s.getTimestamp()) {
                s.setTimestamp(this.document.getTimestamp());
            }
        }

        document.setTimestamp(OffsetDateTime.now());

        return super.add(e);
    }

    @Override
    public boolean addAll(Collection<? extends E> c) {
        throw new UnsupportedOperationException();
    }

}

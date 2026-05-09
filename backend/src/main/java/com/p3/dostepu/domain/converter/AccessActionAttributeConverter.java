package com.p3.dostepu.domain.converter;

import com.p3.dostepu.domain.entity.AccessAction;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

/**
 * Maps Java {@link AccessAction} to DB values (lowercase with underscores), matching
 * {@code 01-schema.sql} and SQL that filters on {@code open_attempt}, {@code failure}, etc.
 */
@Converter(autoApply = false)
public class AccessActionAttributeConverter implements AttributeConverter<AccessAction, String> {

  @Override
  public String convertToDatabaseColumn(AccessAction attribute) {
    return attribute == null ? null : attribute.name().toLowerCase();
  }

  @Override
  public AccessAction convertToEntityAttribute(String db) {
    return db == null ? null : AccessAction.valueOf(db.toUpperCase());
  }
}

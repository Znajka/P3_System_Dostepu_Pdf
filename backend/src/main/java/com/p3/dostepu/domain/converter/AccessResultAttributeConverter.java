package com.p3.dostepu.domain.converter;

import com.p3.dostepu.domain.entity.AccessResult;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

/** Maps {@link AccessResult} to lowercase DB strings ({@code success}, {@code failure}). */
@Converter(autoApply = false)
public class AccessResultAttributeConverter implements AttributeConverter<AccessResult, String> {

  @Override
  public String convertToDatabaseColumn(AccessResult attribute) {
    return attribute == null ? null : attribute.name().toLowerCase();
  }

  @Override
  public AccessResult convertToEntityAttribute(String db) {
    return db == null ? null : AccessResult.valueOf(db.toUpperCase());
  }
}

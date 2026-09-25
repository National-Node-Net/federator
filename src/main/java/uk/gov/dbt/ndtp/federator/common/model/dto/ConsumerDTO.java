/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.common.model.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import java.util.ArrayList;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * DTO for consumerId entity.
 */
@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ConsumerDTO {

    @Builder.Default
    private List<AttributesDTO> attributes = new ArrayList<>();

    @Builder.Default
    private List<PolicyAttributeDTO> policyAttributes = new ArrayList<>();

    private OrganisationDTO organisation;

    @JsonIgnore
    private Long id;

    private String name;

    @JsonIgnore
    private Long orgId;

    private String scheduleType;

    private String scheduleExpression;

    private String idpClientId;
}

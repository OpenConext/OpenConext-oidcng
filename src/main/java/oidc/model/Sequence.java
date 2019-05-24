package oidc.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.mongodb.core.mapping.Document;

import java.io.Serializable;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Document(collection = "sequences")
public class Sequence implements Serializable {

    @Transient
    public static final String ID_VALUE = Sequence.class.getName().toLowerCase();

    @Id
    private String _id;

    private Long value;

}
